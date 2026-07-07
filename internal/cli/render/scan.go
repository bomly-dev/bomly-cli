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

// Scan returns the compact human-readable text report for a scan command.
// failOn is the active fail-on constraint list from config; N/A-severity
// findings (e.g. unknown-license) are suppressed unless "any" is present.
// subprojectSummary is an optional pre-computed line like "Discovered 2
// subprojects: web (npm), api (go)" shown before the package count.
// fallbackNotices are pre-computed FallbackNotices lines shown after it.
func Scan(g *sdk.Graph, registry *sdk.PackageRegistry, findings []sdk.Finding, matcherStats []sdk.MatcherStats, enrichEnabled, auditEnabled, reachabilityEnabled bool, failOn []string, subprojectSummary string, fallbackNotices []string) string {
	var b strings.Builder

	if g == nil {
		return "(empty graph)"
	}

	if subprojectSummary != "" {
		fmt.Fprintf(&b, "%s\n", Style(subprojectSummary, Dim))
	}
	for _, notice := range fallbackNotices {
		fmt.Fprintf(&b, "%s\n", Style("⚠ "+notice, Yellow))
	}

	roots, direct, transitive := scanRelationshipCounts(g)
	runtimeCount, developmentCount, _ := scanScopeCounts(g)

	// Package count line: ✓ N packages in M manifests  (D direct, T transitive)
	checkmark := Style("✓", Green)
	countPart := Style(fmt.Sprintf("%d", g.Size()), Cyan, Bold)
	manifestWord := "manifest"
	if roots != 1 {
		manifestWord = "manifests"
	}
	manifestPart := Style(fmt.Sprintf("in %d %s", roots, manifestWord), Dim)
	detailPart := Style(fmt.Sprintf("(%d direct, %d transitive)", direct, transitive), Dim)
	fmt.Fprintf(&b, "%s %s packages %s   %s\n", checkmark, countPart, manifestPart, detailPart)

	// Scopes line
	fmt.Fprintf(&b, "  %s\n", Style(fmt.Sprintf("scopes: runtime %d · dev %d", runtimeCount, developmentCount), Dim))

	// Enrichment line
	if enrichEnabled && len(matcherStats) > 0 {
		sources := make([]string, 0, len(matcherStats))
		seen := make(map[string]struct{})
		for _, stat := range matcherStats {
			label := strings.TrimSpace(stat.DisplayName)
			if label == "" {
				label = strings.TrimSpace(stat.Name)
			}
			if label != "" {
				if _, ok := seen[label]; !ok {
					seen[label] = struct{}{}
					sources = append(sources, label)
				}
			}
		}
		if len(sources) > 0 {
			fmt.Fprintf(&b, "%s %s\n", checkmark, Style("Enriched via "+strings.Join(sources, ", "), Green))
		}
	}

	// Top-level dependencies (direct only) — blank line before the section.
	if table := renderDirectDepsTable(g, registry); table != "" {
		b.WriteString("\n")
		b.WriteString(table)
	}

	// Findings section — blank line before it; N/A-severity findings (e.g.
	// unknown-license policy results) are hidden unless fail-on is "any",
	// matching the principle that display follows enforcement policy.
	if len(findings) > 0 {
		if section := renderCompactFindings(findings, registry, reachabilityEnabled, failOnIncludesAny(failOn)); section != "" {
			b.WriteString("\n")
			b.WriteString(section)
		}
	}

	return b.String()
}

// FallbackNotices returns one human-readable line per manifest that was
// resolved by a fallback detector after its planned primary detector failed,
// e.g. "maven-detector unavailable (not ready: java executable not found on
// PATH) — resolved pom.xml with syft-detector; transitive dependencies may be
// missing". Returns nil when no manifest carries fallback provenance.
func FallbackNotices(manifests []output.ScanManifest) []string {
	var notices []string
	for _, m := range manifests {
		if m.Resolution == nil || m.Resolution.Fallback == nil {
			continue
		}
		fallback := m.Resolution.Fallback
		var b strings.Builder
		fmt.Fprintf(&b, "%s unavailable", fallback.From)
		if reason := strings.TrimSpace(fallback.Reason); reason != "" {
			fmt.Fprintf(&b, " (%s)", reason)
		}
		fmt.Fprintf(&b, " — resolved %s with %s; transitive dependencies may be missing", m.Path, m.Detector)
		notices = append(notices, b.String())
	}
	return notices
}

// BuildSubprojectSummary returns a human-readable line like
// "Discovered 2 subprojects: web (npm), api (go)" from the scan manifests.
// Returns "" when no named subprojects are present (e.g. single-root repos).
func BuildSubprojectSummary(manifests []output.ScanManifest) string {
	type entry struct {
		name string
		pm   string
	}
	seen := make(map[string]struct{})
	var entries []entry
	for _, m := range manifests {
		name := strings.TrimSpace(m.Subproject)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		pm := strings.TrimSpace(m.PackageManager.Name())
		entries = append(entries, entry{name: name, pm: pm})
	}
	if len(entries) == 0 {
		return ""
	}
	word := "subproject"
	if len(entries) > 1 {
		word = "subprojects"
	}
	labels := make([]string, 0, len(entries))
	for _, e := range entries {
		label := e.name
		if e.pm != "" {
			label += " (" + e.pm + ")"
		}
		labels = append(labels, label)
	}
	return fmt.Sprintf("Discovered %d %s: %s", len(entries), word, strings.Join(labels, ", "))
}

// renderDirectDepsTable renders the "Top-level dependencies" section showing
// only packages that are direct dependents of a root node.
func renderDirectDepsTable(g *sdk.Graph, registry *sdk.PackageRegistry) string {
	if g == nil || g.Size() == 0 {
		return ""
	}

	rootIDs := make(map[string]struct{})
	for _, root := range g.Roots() {
		if root != nil {
			rootIDs[root.ID] = struct{}{}
		}
	}

	type row struct {
		name    string
		version string
		license string
		scope   string
		vulns   string
	}
	var rows []row
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
		for _, dep := range dependents {
			if dep != nil {
				if _, isRoot := rootIDs[dep.ID]; isRoot {
					isDirect = true
					break
				}
			}
		}
		if !isDirect {
			continue
		}

		licenseIdents := make([]string, 0, 2)
		for _, lic := range licensesForDependency(pkg, registry) {
			if id := graphLicenseIdentifier(lic); id != "" {
				licenseIdents = append(licenseIdents, id)
				break // show only the primary license
			}
		}
		license := "-"
		if len(licenseIdents) > 0 {
			license = licenseIdents[0]
		}

		scope := string(pkg.PrimaryScope())
		if scope == "" {
			scope = "-"
		}
		version := pkg.Version
		if version == "" {
			version = "-"
		}
		rows = append(rows, row{
			name:    pkg.DisplayName(),
			version: version,
			license: license,
			scope:   scope,
			vulns:   formatDepVulnCounts(pkg, registry),
		})
	}

	if len(rows) == 0 {
		return ""
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].name < rows[j].name
	})

	const maxRows = 20
	overflow := 0
	if len(rows) > maxRows {
		overflow = len(rows) - maxRows
		rows = rows[:maxRows]
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", Style("Top-level dependencies", Bold))
	tw := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)
	// Headers are written without ANSI codes so tabwriter measures visible
	// widths correctly; the column values in data rows are also plain text
	// except for the VULNS column which uses colour only on the counts.
	fmt.Fprintf(tw, "  NAME\tVERSION\tLICENSE\tSCOPE\tVULNS\n")
	for _, r := range rows {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", r.name, r.version, r.license, r.scope, r.vulns)
	}
	_ = tw.Flush()
	if overflow > 0 {
		fmt.Fprintf(&b, "  %s\n", Style(fmt.Sprintf("… and %d more (use --json for full list)", overflow), Dim))
	}
	return b.String()
}

// failOnIncludesAny reports whether the fail-on constraint list contains "any",
// which means every severity level (including N/A) should be enforced.
func failOnIncludesAny(failOn []string) bool {
	for _, v := range failOn {
		if strings.ToLower(strings.TrimSpace(v)) == "any" {
			return true
		}
	}
	return false
}

// renderCompactFindings renders the "Findings" section with aligned columns.
// When showNASeverity is false, findings with N/A or empty severity are omitted.
func renderCompactFindings(findings []sdk.Finding, registry *sdk.PackageRegistry, reachabilityEnabled bool, showNASeverity bool) string {
	type findingRow struct {
		severity string
		id       string
		pkg      string
	}

	rows := make([]findingRow, 0, len(findings))
	maxIDWidth := 0
	for _, f := range findings {
		sev := strings.ToLower(strings.TrimSpace(string(f.Severity)))
		if !showNASeverity && (sev == "n/a" || sev == "") {
			continue
		}
		regPkg, _ := lookupFindingPkgAndVuln(registry, f)
		pkgName := f.PackageRef
		if regPkg != nil && regPkg.Name != "" {
			if regPkg.Version != "" {
				pkgName = regPkg.Name + "@" + regPkg.Version
			} else {
				pkgName = regPkg.Name
			}
		}
		if pkgName == "" {
			pkgName = "-"
		}
		rows = append(rows, findingRow{severity: string(f.Severity), id: f.ID, pkg: pkgName})
		if l := len(f.ID); l > maxIDWidth {
			maxIDWidth = l
		}
	}
	if len(rows) == 0 {
		return ""
	}

	sort.Slice(rows, func(i, j int) bool {
		si := severityRankTable(rows[i].severity)
		sj := severityRankTable(rows[j].severity)
		if si != sj {
			return si < sj
		}
		if rows[i].id != rows[j].id {
			return rows[i].id < rows[j].id
		}
		return rows[i].pkg < rows[j].pkg
	})

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", Style("Findings", Bold))
	for _, r := range rows {
		fmt.Fprintf(&b, "  %s  %-*s  %s\n", severityLabelFixed(r.severity), maxIDWidth, r.id, r.pkg)
	}
	return b.String()
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

// formatDepVulnCounts returns a compact coloured vuln-count string like "1C 2H" for a
// direct dependency. Returns "-" when the registry has no vulnerability data.
func formatDepVulnCounts(dep *sdk.Dependency, registry *sdk.PackageRegistry) string {
	if registry == nil || dep == nil || dep.PURL == "" {
		return "-"
	}
	regPkg, ok := registry.Get(dep.PURL)
	if !ok || regPkg == nil || len(regPkg.Vulnerabilities) == 0 {
		return "-"
	}
	var critical, high, medium, low int
	for _, v := range regPkg.Vulnerabilities {
		switch strings.ToLower(string(v.ParsedSeverity)) {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}
	var parts []string
	if critical > 0 {
		parts = append(parts, Style(fmt.Sprintf("%dC", critical), Red, Bold))
	}
	if high > 0 {
		parts = append(parts, Style(fmt.Sprintf("%dH", high), Red))
	}
	if medium > 0 {
		parts = append(parts, Style(fmt.Sprintf("%dM", medium), Yellow, Bold))
	}
	if low > 0 {
		parts = append(parts, Style(fmt.Sprintf("%dL", low), Cyan))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
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
