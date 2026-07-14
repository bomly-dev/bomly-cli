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
// manifests are the scan manifests the run produced; when they span
// subprojects or modules a grouped manifest tree is rendered after the
// scopes line. fallbackNotices are pre-computed FallbackNotices lines.
func Scan(g *sdk.Graph, registry *sdk.PackageRegistry, findings []sdk.Finding, matcherStats []sdk.MatcherStats, enrichEnabled, auditEnabled, reachabilityEnabled bool, failOn []string, manifests []output.ScanManifest, fallbackNotices []string) string {
	var b strings.Builder

	if g == nil {
		return "(empty graph)"
	}

	for _, notice := range fallbackNotices {
		fmt.Fprintf(&b, "%s\n", Style("⚠ "+notice, Yellow))
	}

	_, direct, transitive := scanRelationshipCounts(g)
	runtimeCount, developmentCount, unscopedCount := scanScopeCounts(g)

	// Package count line: the total counts dependencies only — project and
	// module nodes are structure, not packages — so the relationship and
	// scope distributions always sum to it: total = direct + transitive =
	// runtime + dev (+ unscoped).
	checkmark := Style("✓", Green)
	countPart := Style(fmt.Sprintf("%d", direct+transitive), Cyan, Bold)
	manifestCount := len(manifests)
	manifestWord := "manifest"
	if manifestCount != 1 {
		manifestWord = "manifests"
	}
	manifestPart := Style(fmt.Sprintf("in %d %s", manifestCount, manifestWord), Dim)
	scopePart := fmt.Sprintf("runtime %d, dev %d", runtimeCount, developmentCount)
	if unscopedCount > 0 {
		scopePart += fmt.Sprintf(", unscoped %d", unscopedCount)
	}
	detailPart := Style(fmt.Sprintf("(%d direct, %d transitive · %s)", direct, transitive, scopePart), Dim)
	fmt.Fprintf(&b, "%s %s packages %s   %s\n", checkmark, countPart, manifestPart, detailPart)

	// Grouped manifest tree — only when the scan spans subprojects or
	// modules; flat single-root scans keep the compact report unchanged.
	if hierarchy := output.BuildHierarchy(manifests); hierarchy.HasGroups() {
		b.WriteString(renderManifestHierarchy(g, hierarchy, manifests))
	}

	// Enrichment line — blank-line separated from the counts block.
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
			fmt.Fprintf(&b, "\n%s %s\n", checkmark, Style("Enriched via "+strings.Join(sources, ", "), Green))
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

// maxFallbackNoticePaths caps how many manifest paths are named in a single
// fallback notice; monorepos where one missing toolchain affects many
// modules would otherwise print one path per module.
const maxFallbackNoticePaths = 5

// FallbackNotices returns one human-readable line per (primary detector,
// reason, fallback detector) group that resolved at least one manifest via a
// fallback detector after its planned primary failed, e.g. "maven-detector
// unavailable (not ready: java executable not found on PATH) — resolved
// pom.xml with syft-detector; transitive dependencies may be missing".
// Manifests sharing the same fallback cause are grouped into a single line
// instead of one per manifest. Returns nil when no manifest carries fallback
// provenance.
func FallbackNotices(manifests []output.ScanManifest) []string {
	type group struct {
		from, reason, detector string
		paths                  []string
	}
	var groups []*group
	index := make(map[string]int)
	for _, m := range manifests {
		if m.Resolution == nil || m.Resolution.Fallback == nil {
			continue
		}
		fallback := m.Resolution.Fallback
		// Reason and Path may originate from scanned repository content
		// (subprocess error text, file names); collapse embedded newlines so
		// a crafted value cannot inject extra lines into rendered output.
		from := collapseWhitespace(fallback.From)
		reason := collapseWhitespace(fallback.Reason)
		detector := collapseWhitespace(m.Detector)
		path := collapseWhitespace(m.Path)
		key := from + "\x00" + reason + "\x00" + detector
		if idx, ok := index[key]; ok {
			groups[idx].paths = append(groups[idx].paths, path)
			continue
		}
		index[key] = len(groups)
		groups = append(groups, &group{from: from, reason: reason, detector: detector, paths: []string{path}})
	}

	if len(groups) == 0 {
		return nil
	}
	notices := make([]string, 0, len(groups))
	for _, g := range groups {
		var b strings.Builder
		fmt.Fprintf(&b, "%s unavailable", g.from)
		if g.reason != "" {
			fmt.Fprintf(&b, " (%s)", g.reason)
		}
		paths := g.paths
		overflow := 0
		if len(paths) > maxFallbackNoticePaths {
			overflow = len(paths) - maxFallbackNoticePaths
			paths = paths[:maxFallbackNoticePaths]
		}
		pathList := strings.Join(paths, ", ")
		if overflow > 0 {
			pathList += fmt.Sprintf(", +%d more", overflow)
		}
		if len(g.paths) == 1 {
			fmt.Fprintf(&b, " — resolved %s with %s; transitive dependencies may be missing", pathList, g.detector)
		} else {
			fmt.Fprintf(&b, " — resolved %d manifests with %s (%s); transitive dependencies may be missing", len(g.paths), g.detector, pathList)
		}
		notices = append(notices, b.String())
	}
	return notices
}

// collapseWhitespace trims and folds runs of whitespace (including
// newlines) into single spaces, so untrusted, multi-line input cannot inject
// extra lines into single-line rendered output.
func collapseWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// renderManifestHierarchy renders the grouped manifest tree shown when a
// scan spans subprojects or modules. Modules nest under the manifest that
// natively resolves them (the workspace lockfile, the reactor pom), and every
// node is named after its package when a root name exists:
//
//	└─ dev.bomly.example:multimodule-parent — 1 package, 2 modules [pom.xml]
//	   ├─ dev.bomly.example:core (module, maven) — 2 packages [core/pom.xml]
//	   └─ dev.bomly.example:web (module, maven) — 6 packages [web/pom.xml]
func renderManifestHierarchy(g *sdk.Graph, hierarchy output.HierarchyNode, manifests []output.ScanManifest) string {
	var b strings.Builder
	type line struct {
		indent string
		text   string
	}
	var lines []line

	pluralize := func(count int, word string) string {
		if count == 1 {
			return fmt.Sprintf("%d %s", count, word)
		}
		return fmt.Sprintf("%d %ss", count, word)
	}
	// packageCount counts a manifest's dependencies, excluding structural
	// nodes (graph roots and project/module application nodes): they are
	// structure, not packages, so per-manifest counts stay consistent with
	// the header total.
	structural := topLevelParentIDs(g)
	packageCount := func(manifest output.ScanManifest) int {
		count := 0
		for _, dep := range manifest.Dependencies {
			if _, isStructural := structural[dep.ID]; isStructural {
				continue
			}
			count++
		}
		return count
	}
	// manifestLabel names a manifest line after its package when a root name
	// exists (a manifest and its project/module are one thing), keeping the
	// manifest path as a bracketed hint. moduleCount > 0 marks a parent
	// manifest whose modules nest beneath it.
	manifestLabel := func(index, moduleCount int, baseDir string) string {
		manifest := manifests[index]
		path := strings.TrimSpace(manifest.Path)
		if baseDir != "" && baseDir != "." {
			path = strings.TrimPrefix(path, baseDir+"/")
		}
		label := output.ManifestRootName(manifest)
		if label == "" {
			label = path
			path = ""
		}
		label += " — " + pluralize(packageCount(manifest), "package")
		if moduleCount > 0 {
			label += ", " + pluralize(moduleCount, "module")
		}
		if path != "" {
			label += " [" + path + "]"
		}
		return label
	}
	groupLabel := func(node output.HierarchyNode) string {
		pm := ""
		if len(node.ManifestIndexes) > 0 {
			pm = strings.TrimSpace(manifests[node.ManifestIndexes[0]].PackageManager.Name())
		}
		label := fmt.Sprintf("%s (%s", node.Label, node.Kind)
		if pm != "" {
			label += ", " + pm
		}
		return label + ")"
	}
	// mergedGroupLabel renders a single-manifest group as one merged node,
	// preferring the package's own name over the directory, with the manifest
	// path as a hint — a module and its manifest are one thing to the user.
	mergedGroupLabel := func(node output.HierarchyNode) string {
		manifest := manifests[node.ManifestIndexes[0]]
		name := output.ManifestRootName(manifest)
		if name == "" {
			name = node.Label
		}
		pm := strings.TrimSpace(manifest.PackageManager.Name())
		label := fmt.Sprintf("%s (%s", name, node.Kind)
		if pm != "" {
			label += ", " + pm
		}
		return fmt.Sprintf("%s) — %s [%s]", label, pluralize(packageCount(manifest), "package"), strings.TrimSpace(manifest.Path))
	}

	type child struct {
		text     string
		children []child
	}
	moduleChild := func(group output.HierarchyNode) child {
		return child{text: mergedGroupLabel(group)}
	}
	var nodeChildren func(node output.HierarchyNode) []child
	nodeChildren = func(node output.HierarchyNode) []child {
		// Modules nest under the manifest that resolves them; unattached
		// modules and subproject nodes stay children of the node itself.
		attached := map[int][]child{}
		var unattached []child
		var subprojects []child
		for _, group := range node.Children {
			if group.Kind == output.ManifestNodeModule && len(group.Children) == 0 && len(group.ManifestIndexes) == 1 {
				if group.AttachedManifest >= 0 {
					attached[group.AttachedManifest] = append(attached[group.AttachedManifest], moduleChild(group))
				} else {
					unattached = append(unattached, moduleChild(group))
				}
				continue
			}
			subprojects = append(subprojects, child{text: groupLabel(group), children: nodeChildren(group)})
		}
		children := make([]child, 0, len(node.ManifestIndexes)+len(node.Children))
		for _, index := range node.ManifestIndexes {
			modules := attached[index]
			children = append(children, child{text: manifestLabel(index, len(modules), node.Dir), children: modules})
		}
		children = append(children, unattached...)
		children = append(children, subprojects...)
		return children
	}

	var emit func(children []child, indent string)
	emit = func(children []child, indent string) {
		for i, c := range children {
			connector, continuation := "├─ ", "│  "
			if i == len(children)-1 {
				connector, continuation = "└─ ", "   "
			}
			lines = append(lines, line{indent: indent + connector, text: c.text})
			if len(c.children) > 0 {
				emit(c.children, indent+continuation)
			}
		}
	}
	emit(nodeChildren(hierarchy), "  ")

	for _, l := range lines {
		fmt.Fprintf(&b, "%s%s\n", Style(l.indent, Dim), l.text)
	}
	return b.String()
}

// topLevelParentIDs returns the nodes whose direct children count as
// "top-level" dependencies: graph roots plus every application-type node.
// Workspace members and reactor modules are application nodes that may have
// inbound edges (a sibling depends on them), so a roots-only view would hide
// every non-root module's direct dependencies.
func topLevelParentIDs(g *sdk.Graph) map[string]struct{} {
	parents := make(map[string]struct{})
	for _, root := range g.Roots() {
		if root != nil {
			parents[root.ID] = struct{}{}
		}
	}
	for _, pkg := range g.Nodes() {
		if pkg == nil {
			continue
		}
		if pkg.Type == sdk.PackageTypeApplication {
			parents[pkg.ID] = struct{}{}
		}
	}
	return parents
}

// renderDirectDepsTable renders the "Top-level dependencies" section showing
// packages that are direct dependencies of any top-level parent — the scan
// roots and every module/application node — so multi-module scans list each
// module's direct dependencies, not only the root's.
func renderDirectDepsTable(g *sdk.Graph, registry *sdk.PackageRegistry) string {
	if g == nil || g.Size() == 0 {
		return ""
	}

	rootIDs := topLevelParentIDs(g)

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
	rootIDs := topLevelParentIDs(g)
	roots = len(rootIDs)
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

// scanScopeCounts buckets dependencies by scope over the same node set the
// relationship counts cover (structural project/module nodes excluded), so
// runtime + dev + unscoped always equals direct + transitive.
func scanScopeCounts(g *sdk.Graph) (runtimeCount, developmentCount, unscopedCount int) {
	if g == nil {
		return 0, 0, 0
	}
	structural := topLevelParentIDs(g)
	for _, pkg := range g.Nodes() {
		if pkg == nil {
			continue
		}
		if _, isStructural := structural[pkg.ID]; isStructural {
			continue
		}
		switch pkg.PrimaryScope() {
		case sdk.ScopeRuntime:
			runtimeCount++
		case sdk.ScopeDevelopment:
			developmentCount++
		default:
			unscopedCount++
		}
	}
	return runtimeCount, developmentCount, unscopedCount
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
