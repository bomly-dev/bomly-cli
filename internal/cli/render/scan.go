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
func Scan(manifests []output.ScanManifest, g *sdk.Graph, findings []sdk.Finding, enrichEnabled, auditEnabled, reachabilityEnabled bool) string {
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
	fmt.Fprintf(&b, "  Vulnerability enrichment: %s\n", formatEnrichmentSummary(g, enrichEnabled))
	fmt.Fprintf(&b, "  Policy findings: %s\n", formatAuditSummary(summary, auditEnabled))
	if reachabilityEnabled {
		fmt.Fprintf(&b, "  Reachability: %s\n", formatReachabilitySummary(g))
	}
	fmt.Fprintf(&b, "  Unique licenses: %d\n", scanUniqueLicenseCount(g))

	b.WriteString("\nManifests\n")
	b.WriteString(renderScanManifestTable(manifests))

	b.WriteString("\nDependency Inventory\n")
	b.WriteString(renderScanGraphTable(g))

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
			pkgI, pkgJ := "", ""
			if sorted[i].Package != nil {
				pkgI = sorted[i].Package.DisplayName()
			}
			if sorted[j].Package != nil {
				pkgJ = sorted[j].Package.DisplayName()
			}
			return pkgI < pkgJ
		})
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		if reachabilityEnabled {
			_, _ = fmt.Fprintln(tw, "SEVERITY\tID\tPACKAGE\tREACHABILITY\tFIXED IN\tEXPLOITABILITY\tTITLE\tSOURCE")
		} else {
			_, _ = fmt.Fprintln(tw, "SEVERITY\tID\tPACKAGE\tFIXED IN\tEXPLOITABILITY\tTITLE\tSOURCE")
		}
		for _, f := range sorted {
			pkgName := "-"
			if f.Package != nil {
				pkgName = f.Package.DisplayName()
				if f.Package.Version != "" {
					pkgName += "@" + f.Package.Version
				}
			}
			title := f.Title
			if title == "" {
				title = f.ID
			}
			if len(title) > 60 {
				title = title[:57] + "..."
			}
			fixedIn := ValueOrDash(fixedVersionSummary(f.FixedIn, f.FixedVersions))
			exploitability := ValueOrDash(exploitabilitySummary(f.KEVExploited, f.KnownExploited, f.RiskScore))
			if reachabilityEnabled {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					f.Severity, f.ID, pkgName, formatReachabilityCell(f.Reachability), fixedIn, exploitability, title, f.Source)
			} else {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					f.Severity, f.ID, pkgName, fixedIn, exploitability, title, f.Source)
			}
		}
		_ = tw.Flush()
	}

	b.WriteString("\nLicense Overview\n")
	b.WriteString(renderUniqueLicensesTable(g))

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

func renderUniqueLicensesTable(g *sdk.Graph) string {
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
	for _, pkg := range g.Packages() {
		if pkg == nil {
			continue
		}
		for _, license := range pkg.Licenses {
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
// graph's package vulnerabilities for the executive summary.
func formatReachabilitySummary(g *sdk.Graph) string {
	if g == nil || g.Size() == 0 {
		return "no vulnerabilities analyzed"
	}
	var reachable, unreachable, unknown, notApplicable, total int
	for _, pkg := range g.Packages() {
		if pkg == nil {
			continue
		}
		for _, vuln := range pkg.Vulnerabilities {
			if vuln.Reachability == nil {
				continue
			}
			total++
			switch vuln.Reachability.Status {
			case sdk.ReachabilityReachable:
				reachable++
			case sdk.ReachabilityUnreachable:
				unreachable++
			case sdk.ReachabilityNotApplicable:
				notApplicable++
			default:
				unknown++
			}
		}
	}
	if total == 0 {
		return "enabled (no analyzer ran on any vulnerability)"
	}
	parts := make([]string, 0, 4)
	if reachable > 0 {
		parts = append(parts, fmt.Sprintf("%d reachable", reachable))
	}
	if unreachable > 0 {
		parts = append(parts, fmt.Sprintf("%d unreachable", unreachable))
	}
	if unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", unknown))
	}
	if notApplicable > 0 {
		parts = append(parts, fmt.Sprintf("%d not_applicable", notApplicable))
	}
	return fmt.Sprintf("%d analyzed (%s)", total, strings.Join(parts, ", "))
}

func formatEnrichmentSummary(g *sdk.Graph, enrichEnabled bool) string {
	if g == nil || g.Size() == 0 {
		if !enrichEnabled {
			return "disabled"
		}
		return "enabled"
	}
	packagesWithVulnerabilities := 0
	totalVulnerabilities := 0
	for _, pkg := range g.Packages() {
		if pkg == nil || len(pkg.Vulnerabilities) == 0 {
			continue
		}
		packagesWithVulnerabilities++
		totalVulnerabilities += len(pkg.Vulnerabilities)
	}
	if !enrichEnabled {
		if totalVulnerabilities > 0 {
			return fmt.Sprintf("%d matched across %d packages (present from existing package data)", totalVulnerabilities, packagesWithVulnerabilities)
		}
		return "disabled"
	}
	if totalVulnerabilities == 0 {
		return "enabled (no matched vulnerabilities)"
	}
	return fmt.Sprintf("%d matched across %d packages", totalVulnerabilities, packagesWithVulnerabilities)
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
	for _, pkg := range g.Packages() {
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
	for _, pkg := range g.Packages() {
		if pkg == nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(pkg.Scope)) {
		case string(sdk.ScopeRuntime):
			runtimeCount++
		case string(sdk.ScopeDevelopment):
			developmentCount++
		default:
			unknownCount++
		}
	}
	return runtimeCount, developmentCount, unknownCount
}

func scanUniqueLicenseCount(g *sdk.Graph) int {
	if g == nil {
		return 0
	}
	licenseSet := make(map[string]struct{})
	for _, pkg := range g.Packages() {
		for _, value := range pkg.LicenseValues() {
			licenseSet[value] = struct{}{}
		}
	}
	return len(licenseSet)
}

func renderScanGraphTable(g *sdk.Graph) string {
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
	for _, pkg := range g.Packages() {
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

		rows = append(rows, row{
			name:         pkg.DisplayName(),
			version:      pkg.Version,
			scope:        pkg.Scope,
			relationship: relationship,
			licenses:     packageLicenseIdentifiers(pkg),
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
