package render

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// ScanGraphDisplayName returns a label for the scan target derived from g's
// single root, or fallback when g has zero or multiple roots.
func ScanGraphDisplayName(g *sdk.Graph, fallback string) string {
	if g == nil {
		return fallback
	}
	roots := g.Roots()
	if len(roots) != 1 {
		return fallback
	}
	if roots[0].QualifiedName() != "" {
		return roots[0].QualifiedName()
	}
	if roots[0].ID != "" {
		return roots[0].ID
	}
	return fallback
}

// Scan returns the human-readable text report for a scan command.
// registry, when non-nil, supplies matching-stage enrichment (vulnerabilities,
// scorecards, licenses learned during matching) which is folded into the
// rendered summaries and tables. Pass nil for a detection-only render.
func Scan(manifests []output.ScanManifest, g *sdk.Graph, registry *sdk.PackageRegistry, findings []sdk.Finding, enrichEnabled, auditEnabled, reachabilityEnabled bool) string {
	var b strings.Builder

	if g == nil {
		return "(empty graph)"
	}

	summary := output.SummaryFromFindings(findings)
	roots, direct, transitive := scanRelationshipCounts(g)
	runtimeCount, developmentCount, unknownScopeCount := scanScopeCounts(g)
	fmt.Fprintf(&b, "Executive Summary\n")
	fmt.Fprintf(&b, "  Packages: %d total\n", g.Size())
	fmt.Fprintf(&b, "  Relationships: %d root, %d direct, %d transitive\n", roots, direct, transitive)
	fmt.Fprintf(&b, "  Scopes: %d runtime, %d development, %d unspecified\n", runtimeCount, developmentCount, unknownScopeCount)
	fmt.Fprintf(&b, "  Vulnerability enrichment: %s\n", formatEnrichmentSummary(registry, enrichEnabled))
	fmt.Fprintf(&b, "  Policy findings: %s\n", formatAuditSummary(summary, auditEnabled))
	if reachabilityEnabled {
		fmt.Fprintf(&b, "  Reachability: %s\n", formatReachabilitySummary(registry))
	}
	fmt.Fprintf(&b, "  Unique licenses: %d\n", scanUniqueLicenseCount(g, registry))
	if scoredCount, totalRepos := scorecardCounts(registry); totalRepos > 0 {
		fmt.Fprintf(&b, "  Project posture: %d Scorecard run(s) across %d package(s)\n", totalRepos, scoredCount)
	}

	b.WriteString("\nManifests\n")
	b.WriteString(renderScanManifestTable(manifests))

	b.WriteString("\nDependency Inventory\n")
	b.WriteString(renderScanGraphTable(g, registry))

	b.WriteString("\n\nPolicy Findings\n")
	if len(findings) == 0 {
		if auditEnabled {
			b.WriteString("No policy findings.\n")
		} else {
			b.WriteString("Policy evaluation not enabled. Run with --audit to create findings.\n")
		}
	} else {
		sorted := make([]sdk.Finding, len(findings))
		copy(sorted, findings)
		sort.Slice(sorted, func(i, j int) bool {
			si := severityRankTable(sorted[i].Severity)
			sj := severityRankTable(sorted[j].Severity)
			if si != sj {
				return si < sj
			}
			if sorted[i].ID != sorted[j].ID {
				return sorted[i].ID < sorted[j].ID
			}
			// TODO(batch-6): plumb the registry through so we can resolve
			// PackageRef → DisplayName for prettier ordering.
			return sorted[i].PackageRef < sorted[j].PackageRef
		})
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		if reachabilityEnabled {
			_, _ = fmt.Fprintln(tw, "SEVERITY\tID\tPACKAGE\tREACHABILITY\tFIXED IN\tEXPLOITABILITY\tTITLE\tSOURCE")
		} else {
			_, _ = fmt.Fprintln(tw, "SEVERITY\tID\tPACKAGE\tFIXED IN\tEXPLOITABILITY\tTITLE\tSOURCE")
		}
		for _, f := range sorted {
			pkg, vuln := lookupFindingPkgAndVuln(registry, f)
			pkgName := f.PackageRef
			if pkg != nil && pkg.Name != "" {
				if pkg.Version != "" {
					pkgName = pkg.Name + "@" + pkg.Version
				} else {
					pkgName = pkg.Name
				}
			}
			if pkgName == "" {
				pkgName = "-"
			}
			title := f.Title
			if title == "" && vuln != nil {
				title = vuln.Title
			}
			if title == "" {
				title = f.ID
			}
			if len(title) > 60 {
				title = title[:57] + "..."
			}
			fixedIn := "-"
			exploitability := "-"
			reachCell := "-"
			if vuln != nil {
				if vuln.FixedIn != "" {
					fixedIn = vuln.FixedIn
				} else if len(vuln.FixedVersions) > 0 {
					fixedIn = vuln.FixedVersions[0]
				}
				if vuln.KEVExploited {
					exploitability = "KEV"
				} else if len(vuln.EPSS) > 0 {
					exploitability = fmt.Sprintf("EPSS %.2f", vuln.EPSS[0].EPSS)
				}
				if reachabilityEnabled {
					reachCell = formatReachabilityCell(vuln.Reachability)
				}
			}
			if reachabilityEnabled {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					f.Severity, f.ID, pkgName, reachCell, fixedIn, exploitability, title, f.Source)
			} else {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					f.Severity, f.ID, pkgName, fixedIn, exploitability, title, f.Source)
			}
		}
		_ = tw.Flush()
	}

	b.WriteString("\nLicense Overview\n")
	b.WriteString(renderUniqueLicensesTable(g, registry))

	if posture := renderScorecardTable(registry); posture != "" {
		b.WriteString("\n\nProject Posture\n")
		b.WriteString(posture)
	}

	report := strings.TrimRight(b.String(), "\n")
	return report
}

func severityRankTable(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// lookupFindingPkgAndVuln resolves a Finding against the registry, returning
// the matched Package and the specific Vulnerability it references (if any).
// Either return value may be nil.
func lookupFindingPkgAndVuln(registry *sdk.PackageRegistry, f sdk.Finding) (*sdk.Package, *sdk.Vulnerability) {
	if registry == nil || f.PackageRef == "" {
		return nil, nil
	}
	pkg, ok := registry.Get(f.PackageRef)
	if !ok || pkg == nil {
		return nil, nil
	}
	vulnID := f.VulnerabilityID
	if vulnID == "" {
		vulnID = f.ID
	}
	if vulnID == "" {
		return pkg, nil
	}
	for i := range pkg.Vulnerabilities {
		v := &pkg.Vulnerabilities[i]
		if v.ID == vulnID {
			return pkg, v
		}
		for _, alias := range v.Aliases {
			if alias == vulnID {
				return pkg, v
			}
		}
	}
	return pkg, nil
}

// licensesForDependency returns the licenses to render for a dependency:
// matching-stage licenses on the registry package when present, otherwise
// the detection-time licenses stashed on the dependency.
func licensesForDependency(dep *sdk.Dependency, registry *sdk.PackageRegistry) []sdk.PackageLicense {
	if registry != nil && dep != nil && dep.PURL != "" {
		if pkg, ok := registry.Get(dep.PURL); ok && pkg != nil && len(pkg.Licenses) > 0 {
			return pkg.Licenses
		}
	}
	return sdk.DetectionLicenses(dep)
}

func renderUniqueLicensesTable(g *sdk.Graph, registry *sdk.PackageRegistry) string {
	if g == nil || g.Size() == 0 {
		return "(no packages)\n"
	}

	type licenseSummaryRow struct {
		identifier string
		spdx       string
		value      string
		sourceType string
		packages   map[string]struct{}
	}
	rowsByIdentifier := make(map[string]*licenseSummaryRow)
	for _, pkg := range g.Nodes() {
		if pkg == nil {
			continue
		}
		for _, license := range licensesForDependency(pkg, registry) {
			identifier := graphLicenseIdentifier(license)
			if identifier == "" {
				continue
			}
			row, ok := rowsByIdentifier[identifier]
			if !ok {
				row = &licenseSummaryRow{
					identifier: identifier,
					packages:   make(map[string]struct{}),
				}
				rowsByIdentifier[identifier] = row
			}
			if row.spdx == "" {
				row.spdx = strings.TrimSpace(license.SPDXExpression)
			}
			if row.value == "" {
				row.value = strings.TrimSpace(license.Value)
			}
			if row.sourceType == "" {
				row.sourceType = strings.TrimSpace(license.Type)
			}
			row.packages[pkg.ID] = struct{}{}
		}
	}
	if len(rowsByIdentifier) == 0 {
		return "(no license information available)\n"
	}

	rows := make([]licenseSummaryRow, 0, len(rowsByIdentifier))
	for _, row := range rowsByIdentifier {
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].identifier != rows[j].identifier {
			return rows[i].identifier < rows[j].identifier
		}
		if len(rows[i].packages) != len(rows[j].packages) {
			return len(rows[i].packages) > len(rows[j].packages)
		}
		return rows[i].sourceType < rows[j].sourceType
	})
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "IDENTIFIER\tSPDX\tVALUE\tSOURCE\tPACKAGES")
	for _, row := range rows {
		_, _ = fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%d\n",
			ValueOrDash(row.identifier),
			ValueOrDash(row.spdx),
			ValueOrDash(row.value),
			ValueOrDash(row.sourceType),
			len(row.packages),
		)
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func formatAuditSummary(summary *output.AuditSummary, auditEnabled bool) string {
	if summary == nil || summary.Total == 0 {
		if auditEnabled {
			return "none"
		}
		return "not audited"
	}
	parts := make([]string, 0, 5)
	if summary.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", summary.Critical))
	}
	if summary.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", summary.High))
	}
	if summary.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", summary.Medium))
	}
	if summary.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", summary.Low))
	}
	if summary.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", summary.Unknown))
	}
	return fmt.Sprintf("%d total (%s)", summary.Total, strings.Join(parts, ", "))
}

// formatReachabilityCell renders one Reachability annotation for the
// findings table. Returns "-" when no analyzer ran (nil reachability) so
// the column reads cleanly when only a subset of findings is annotated.
func formatReachabilityCell(r *sdk.Reachability) string {
	if r == nil {
		return "-"
	}
	if r.Tier == "" || r.Tier == sdk.TierNone {
		return string(r.Status)
	}
	return fmt.Sprintf("%s (%s)", r.Status, r.Tier)
}

// formatReachabilitySummary tallies reachability outcomes across the
// registry's vulnerabilities for the executive summary.
func formatReachabilitySummary(registry *sdk.PackageRegistry) string {
	if registry == nil || registry.Len() == 0 {
		return "no vulnerabilities analyzed"
	}
	var reachable, unreachable, unknown int
	for _, pkg := range registry.All() {
		if pkg == nil {
			continue
		}
		for _, v := range pkg.Vulnerabilities {
			if v.Reachability == nil {
				continue
			}
			switch v.Reachability.Status {
			case sdk.ReachabilityReachable:
				reachable++
			case sdk.ReachabilityUnreachable:
				unreachable++
			default:
				unknown++
			}
		}
	}
	total := reachable + unreachable + unknown
	if total == 0 {
		return "no vulnerabilities analyzed"
	}
	return fmt.Sprintf("%d reachable, %d unreachable, %d unknown", reachable, unreachable, unknown)
}

func formatEnrichmentSummary(registry *sdk.PackageRegistry, enrichEnabled bool) string {
	if !enrichEnabled {
		return "disabled"
	}
	if registry == nil {
		return "enabled (no enrichment data available)"
	}
	var packages, vulns int
	for _, pkg := range registry.All() {
		if pkg == nil {
			continue
		}
		if len(pkg.Vulnerabilities) > 0 || pkg.Matched {
			packages++
		}
		vulns += len(pkg.Vulnerabilities)
	}
	return fmt.Sprintf("enabled (%d packages enriched, %d vulnerabilities)", packages, vulns)
}

func renderScanManifestTable(manifests []output.ScanManifest) string {
	if len(manifests) == 0 {
		return "(no manifests)\n"
	}

	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SUBPROJECT\tMANIFEST\tKIND\tMANAGER\tPACKAGES")
	for _, manifest := range manifests {
		subproject := manifest.Subproject
		if subproject == "" {
			subproject = "."
		}
		pathValue := manifest.Path
		if pathValue == "" {
			pathValue = "-"
		}
		kind := manifest.Kind
		if kind == "" {
			kind = "-"
		}
		manager := manifest.PackageManager
		if manager == "" {
			manager = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", subproject, pathValue, kind, manager, len(manifest.Packages))
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func scanRelationshipCounts(g *sdk.Graph) (roots, direct, transitive int) {
	if g == nil {
		return 0, 0, 0
	}
	rootIDs := make(map[string]struct{})
	for _, root := range g.Roots() {
		if root != nil {
			rootIDs[root.ID] = struct{}{}
			roots++
		}
	}
	for _, pkg := range g.Nodes() {
		if pkg == nil {
			continue
		}
		if _, isRoot := rootIDs[pkg.ID]; isRoot {
			continue
		}
		dependents, err := g.Dependents(pkg.ID)
		if err != nil {
			continue
		}
		isDirect := false
		for _, dependent := range dependents {
			if dependent != nil {
				if _, isRoot := rootIDs[dependent.ID]; isRoot {
					isDirect = true
					break
				}
			}
		}
		if isDirect {
			direct++
		} else {
			transitive++
		}
	}
	return roots, direct, transitive
}

func scanScopeCounts(g *sdk.Graph) (runtimeCount, developmentCount, unknownCount int) {
	if g == nil {
		return 0, 0, 0
	}
	for _, pkg := range g.Nodes() {
		if pkg == nil {
			continue
		}
		switch pkg.PrimaryScope() {
		case sdk.ScopeRuntime:
			runtimeCount++
		case sdk.ScopeDevelopment:
			developmentCount++
		default:
			unknownCount++
		}
	}
	return runtimeCount, developmentCount, unknownCount
}

func scanUniqueLicenseCount(g *sdk.Graph, registry *sdk.PackageRegistry) int {
	if g == nil {
		return 0
	}
	licenseSet := make(map[string]struct{})
	for _, pkg := range g.Nodes() {
		for _, license := range licensesForDependency(pkg, registry) {
			switch {
			case strings.TrimSpace(license.SPDXExpression) != "":
				licenseSet[license.SPDXExpression] = struct{}{}
			case strings.TrimSpace(license.Value) != "":
				licenseSet[license.Value] = struct{}{}
			}
		}
	}
	return len(licenseSet)
}

func renderScanGraphTable(g *sdk.Graph, registry *sdk.PackageRegistry) string {
	if g == nil || g.Size() == 0 {
		return "(empty graph)"
	}

	rootIDs := make(map[string]struct{})
	for _, root := range g.Roots() {
		rootIDs[root.ID] = struct{}{}
	}

	type row struct {
		name         string
		version      string
		scope        string
		relationship string
		licenses     string
		id           string
	}

	rows := make([]row, 0, g.Size())
	for _, pkg := range g.Nodes() {
		relationship := "transitive"
		if _, isRoot := rootIDs[pkg.ID]; isRoot {
			relationship = "root"
		} else if dependents, err := g.Dependents(pkg.ID); err == nil {
			for _, dependent := range dependents {
				if _, isRoot := rootIDs[dependent.ID]; isRoot {
					relationship = "direct"
					break
				}
			}
		}

		licenseIdents := make([]string, 0, 4)
		for _, lic := range licensesForDependency(pkg, registry) {
			if id := graphLicenseIdentifier(lic); id != "" {
				licenseIdents = append(licenseIdents, id)
			}
		}
		rows = append(rows, row{
			name:         pkg.DisplayName(),
			version:      pkg.Version,
			scope:        string(pkg.PrimaryScope()),
			relationship: relationship,
			licenses:     strings.Join(licenseIdents, ", "),
			id:           pkg.ID,
		})
	}

	if len(rows) == 0 {
		return "(no dependencies)"
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].relationship != rows[j].relationship {
			return RelationshipOrder(rows[i].relationship) < RelationshipOrder(rows[j].relationship)
		}
		return rows[i].id < rows[j].id
	})

	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PACKAGE\tVERSION\tSCOPE\tRELATIONSHIP\tLICENSES")
	for _, row := range rows {
		version := row.version
		if version == "" {
			version = "-"
		}
		scope := row.scope
		if scope == "" {
			scope = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", row.name, version, scope, row.relationship, ValueOrDash(row.licenses))
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// scorecardCounts returns (packagesEnriched, uniqueRepos) over the registry.
func scorecardCounts(registry *sdk.PackageRegistry) (int, int) {
	if registry == nil {
		return 0, 0
	}
	packages := 0
	repos := make(map[string]struct{})
	for _, pkg := range registry.All() {
		if pkg == nil || pkg.Scorecard == nil {
			continue
		}
		packages++
		if pkg.Scorecard.Repository != "" {
			repos[pkg.Scorecard.Repository] = struct{}{}
		}
	}
	return packages, len(repos)
}

// renderScorecardTable renders one row per unique source repo enriched by the
// scorecard matcher. Returns the empty string when no packages carry a
// Scorecard run, so callers can skip the section header entirely.
func renderScorecardTable(registry *sdk.PackageRegistry) string {
	if registry == nil || registry.Len() == 0 {
		return ""
	}
	type row struct {
		repo     string
		score    float64
		runDate  string
		version  string
		packages int
	}
	byRepo := make(map[string]*row)
	for _, pkg := range registry.All() {
		if pkg == nil || pkg.Scorecard == nil {
			continue
		}
		sc := pkg.Scorecard
		key := sc.Repository
		if key == "" {
			key = pkg.PURL
		}
		r, ok := byRepo[key]
		if !ok {
			r = &row{repo: key, score: -1}
			byRepo[key] = r
		}
		r.packages++
		if sc.AggregateScore > r.score {
			r.score = sc.AggregateScore
		}
		if !sc.RunDate.IsZero() && r.runDate == "" {
			r.runDate = sc.RunDate.Format("2006-01-02")
		}
		if sc.ScorecardVersion != "" && r.version == "" {
			r.version = sc.ScorecardVersion
		}
	}
	if len(byRepo) == 0 {
		return ""
	}
	rows := make([]*row, 0, len(byRepo))
	for _, r := range byRepo {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score < rows[j].score
		}
		return rows[i].repo < rows[j].repo
	})

	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "REPOSITORY\tSCORE\tRUN DATE\tVERSION\tPACKAGES")
	for _, r := range rows {
		score := "n/a"
		if r.score >= 0 {
			score = fmt.Sprintf("%.1f/10", r.score)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n",
			r.repo, score, ValueOrDash(r.runDate), ValueOrDash(r.version), r.packages)
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}

func packageLicenseIdentifiers(pkg *sdk.Package) string {
	if pkg == nil || len(pkg.Licenses) == 0 {
		return ""
	}
	values := make([]string, 0, len(pkg.Licenses))
	for _, license := range pkg.Licenses {
		if identifier := graphLicenseIdentifier(license); identifier != "" {
			values = append(values, identifier)
		}
	}
	if len(values) == 0 {
		return ""
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func graphLicenseIdentifier(license sdk.PackageLicense) string {
	switch {
	case strings.TrimSpace(license.SPDXExpression) != "":
		return strings.TrimSpace(license.SPDXExpression)
	case strings.TrimSpace(license.Value) != "":
		return strings.TrimSpace(license.Value)
	default:
		return ""
	}
}
