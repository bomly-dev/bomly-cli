package tui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func NewScan(project output.ProjectDescriptor, consolidated sdk.ConsolidatedGraph, graphValue *sdk.Graph, findings []sdk.Finding) *scanModel {
	return NewScanNavigator("Bomly Interactive Scan", project, consolidated, graphValue, findings)
}

func NewScanNavigator(titlePrefix string, project output.ProjectDescriptor, consolidated sdk.ConsolidatedGraph, graphValue *sdk.Graph, findings []sdk.Finding) *scanModel {
	manifests := manifestRows(consolidated)
	manifestByID := make(map[string]listPackageRow, len(manifests))
	for _, manifest := range manifests {
		manifestByID[manifest.id] = manifest
	}

	model := &scanModel{
		titlePrefix:       titlePrefix,
		project:           project,
		graphValue:        graphValue,
		explainMode:       strings.Contains(strings.ToLower(titlePrefix), "explain"),
		manifests:         manifests,
		manifestByID:      manifestByID,
		mode:              interactiveScanModeManifests,
		allowManifestExit: len(manifests) > 1,
		findings:          findings,
		activeView:        interactiveScanViewOverview,
		sourceExpanded:    map[string]bool{"root": true},
	}
	if len(manifests) == 1 {
		model.mode = interactiveScanModeComponents
		model.currentManifestID = manifests[0].id
	}
	model.list = model.buildCurrentListModel()
	return model
}

func (m *scanModel) View(width, height int) string {
	if m == nil || m.list == nil {
		return ""
	}
	return m.list.View(width, height)
}

func (m *scanModel) Move(delta int) {
	if m == nil || m.list == nil {
		return
	}
	m.list.Move(delta)
}

func (m *scanModel) ScrollDetails(delta int) {
	if m == nil || m.list == nil {
		return
	}
	m.list.ScrollDetails(delta)
}

func (m *scanModel) Home() {
	if m == nil || m.list == nil {
		return
	}
	m.list.Home()
}

func (m *scanModel) End() {
	if m == nil || m.list == nil {
		return
	}
	m.list.End()
}

func (m *scanModel) BeginSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.BeginSearch()
}

func (m *scanModel) AppendSearch(value string) {
	if m == nil || m.list == nil {
		return
	}
	m.list.AppendSearch(value)
}

func (m *scanModel) BackspaceSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.BackspaceSearch()
}

func (m *scanModel) CancelSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.CancelSearch()
}

func (m *scanModel) ConfirmSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.ConfirmSearch()
}

func (m *scanModel) IsSearching() bool {
	if m == nil || m.list == nil {
		return false
	}
	return m.list.IsSearching()
}

func (m *scanModel) CycleView() {
	if m == nil {
		return
	}
	views := scanViews()
	for idx, view := range views {
		if view == m.activeView {
			m.activeView = views[(idx+1)%len(views)]
			m.list = m.buildCurrentListModel()
			return
		}
	}
	m.activeView = interactiveScanViewOverview
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) SelectView(index int) {
	views := scanViews()
	if m == nil || index < 1 || index > len(views) {
		return
	}
	m.activeView = views[index-1]
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) ToggleSelected() {
	if m == nil || m.list == nil || m.activeView != interactiveScanViewSource {
		return
	}
	visible := m.list.visibleItemIndices()
	if len(visible) == 0 {
		return
	}
	item := m.list.items[visible[m.list.selectedVisibleIndex(visible)]]
	key := sourceKey(item.title)
	if key == "" {
		return
	}
	m.sourceExpanded[key] = !m.sourceExpanded[key]
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) CycleRelationshipFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages || m.mode != interactiveScanModeComponents {
		return
	}
	m.relationshipFilter = nextRelationshipFilter(m.relationshipFilter, m.explainMode)
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) CycleScopeFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages || m.mode != interactiveScanModeComponents {
		return
	}
	m.scopeFilter = nextScopeFilter(m.scopeFilter)
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) CycleSeverityFilter() {
	if m == nil {
		return
	}
	switch m.activeView {
	case interactiveScanViewVulns:
		// always applicable
	case interactiveScanViewPackages:
		if m.mode != interactiveScanModeComponents {
			return
		}
	default:
		return
	}
	m.severityFilter = nextSeverityFilter(m.severityFilter)
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) OpenSelected() {
	if m == nil || m.list == nil || m.activeView != interactiveScanViewPackages || m.mode != interactiveScanModeManifests {
		return
	}
	visible := m.list.visibleItemIndices()
	if len(visible) == 0 {
		return
	}
	item := m.list.items[visible[m.list.selectedVisibleIndex(visible)]]
	manifestID := manifestIDFromTitle(item.title)
	if manifestID == "" {
		for id, manifest := range m.manifestByID {
			if manifest.displayName == item.title {
				manifestID = id
				break
			}
		}
	}
	if manifestID == "" {
		return
	}
	m.mode = interactiveScanModeComponents
	m.currentManifestID = manifestID
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) GoBack() {
	if !m.CanGoBack() {
		return
	}
	m.mode = interactiveScanModeManifests
	m.currentManifestID = ""
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) CanGoBack() bool {
	if m == nil {
		return false
	}
	return m.activeView == interactiveScanViewPackages && m.mode == interactiveScanModeComponents && m.allowManifestExit
}

func (m *scanModel) buildCurrentListModel() *listModel {
	switch m.activeView {
	case interactiveScanViewOverview:
		return m.buildOverviewListModel()
	case interactiveScanViewVulns:
		return m.buildVulnsListModel()
	case interactiveScanViewLicenses:
		return m.buildLicensesListModel()
	case interactiveScanViewFindings:
		return m.buildFindingsListModel()
	case interactiveScanViewSource:
		return m.buildSourceListModel()
	default:
		if m.mode == interactiveScanModeComponents {
			manifest, ok := m.manifestByID[m.currentManifestID]
			if ok {
				return m.buildComponentListModel(manifest)
			}
		}
		return m.buildManifestListModel()
	}
}

func scanViews() []scanView {
	return []scanView{
		interactiveScanViewOverview,
		interactiveScanViewPackages,
		interactiveScanViewVulns,
		interactiveScanViewLicenses,
		interactiveScanViewFindings,
		interactiveScanViewSource,
	}
}

func (m *scanModel) scanSummaryLines(active scanView) []string {
	return []string{
		render.Style(" bomly ", render.BgCyan, render.Blue, render.Bold) + " " +
			render.Style("SCAN", render.BgBlue, render.White, render.Bold) + " " +
			render.Style(valueOrDash(m.project.Name), render.White, render.Bold) + " " +
			render.Style(targetKindLabel(m.project), render.Dim),
		m.tabLine(active),
		m.scanStatusLine(),
	}
}

func (m *scanModel) tabLine(active scanView) string {
	labels := []struct {
		view  scanView
		label string
	}{
		{interactiveScanViewOverview, "Overview"},
		{interactiveScanViewPackages, "Components"},
		{interactiveScanViewVulns, "Vulns"},
		{interactiveScanViewLicenses, "Licenses"},
		{interactiveScanViewFindings, "Findings"},
		{interactiveScanViewSource, "Source"},
	}
	parts := make([]string, 0, len(labels))
	for idx, item := range labels {
		text := fmt.Sprintf("[%d] %s", idx+1, item.label)
		if item.view == active {
			parts = append(parts, render.Style(text, render.Yellow, render.Bold))
		} else {
			parts = append(parts, render.Style(text, render.Dim))
		}
	}
	return strings.Join(parts, render.Style(" | ", render.Dim))
}

func (m *scanModel) scanStatusLine() string {
	stats := scanStats(m.graphValue, m.findings)
	return render.Style("Components: ", render.Dim) + render.Style(fmt.Sprintf("%d", stats.components), render.Cyan, render.Bold) +
		render.Style(" | Vulns: ", render.Dim) + severityText(fmt.Sprintf("%d", stats.vulnerabilities)) +
		render.Style(" | Licenses: ", render.Dim) + render.Style(fmt.Sprintf("%d", stats.licenses), render.Cyan, render.Bold) +
		render.Style(" | Findings: ", render.Dim) + render.Style(fmt.Sprintf("%d", len(m.findings)), render.Cyan, render.Bold)
}

func (m *scanModel) buildManifestListModel() *listModel {
	items := make([]listItem, 0, len(m.manifests))
	for _, manifest := range m.manifests {
		title := manifest.displayName + " [" + manifest.id + "]"
		items = append(items, listItem{
			title:    title,
			subtitle: "manifest",
			details:  manifestDetails(m.graphValue, manifest),
		})
	}

	packageCount := 0
	if m.graphValue != nil {
		packageCount = m.graphValue.Size()
	}

	return &listModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: append(m.scanSummaryLines(interactiveScanViewPackages), []string{
			render.Style(fmt.Sprintf("Manifests %d", len(m.manifests)), render.Cyan, render.Bold),
			render.Style(fmt.Sprintf("Packages  %d", packageCount), render.Cyan, render.Bold),
			render.Style("Project   ", render.Dim) + m.project.Path,
			render.Style("Ecosystem ", render.Dim) + valueOrDash(m.project.Ecosystem),
		}...),
		navigationHelp: interactiveCommonNavigationHelp + "; Enter opens selected manifest",
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; 1-6 switch tabs",
		emptyState:     "No manifests were found in the dependency graph.",
		items:          items,
	}
}

func (m *scanModel) buildOverviewListModel() *listModel {
	stats := scanStats(m.graphValue, m.findings)
	items := []listItem{
		{
			title:    "Target Information",
			subtitle: "overview",
			details: []string{
				render.Style("Target", render.Bold, render.Cyan),
				render.Style("  Name: ", render.Dim) + valueOrDash(m.project.Name),
				render.Style("  Path: ", render.Dim) + valueOrDash(m.project.Path),
				render.Style("  Ecosystem: ", render.Dim) + valueOrDash(m.project.Ecosystem),
				render.Style("  Package manager: ", render.Dim) + valueOrDash(m.project.PackageManager),
				render.Style("  Manifests: ", render.Dim) + fmt.Sprintf("%d", len(m.manifests)),
			},
		},
		{
			title:    "Summary Counts",
			subtitle: "cards",
			details: []string{
				render.Style("Summary", render.Bold, render.Cyan),
				render.Style("  Components: ", render.Dim) + fmt.Sprintf("%d", stats.components),
				render.Style("  Ecosystems: ", render.Dim) + fmt.Sprintf("%d", len(stats.ecosystems)),
				render.Style("  Vulnerabilities: ", render.Dim) + fmt.Sprintf("%d", stats.vulnerabilities),
				render.Style("  Unique licenses: ", render.Dim) + fmt.Sprintf("%d", stats.licenses),
				render.Style("  Findings: ", render.Dim) + fmt.Sprintf("%d", len(m.findings)),
			},
		},
		{
			title:    "Vulnerabilities by Severity",
			subtitle: "distribution",
			details:  distributionDetails("Vulnerability Severity", severityDistribution(m.findings)),
		},
		{
			title:    "Components by Ecosystem",
			subtitle: "distribution",
			details:  distributionDetails("Ecosystem Distribution", stats.ecosystems),
		},
		{
			title:    "Components by License",
			subtitle: "distribution",
			details:  licenseDistributionDetails(m.graphValue),
		},
		{
			title:    "Top Vulnerable Components",
			subtitle: "top",
			details:  topVulnerableComponentDetails(m.findings),
		},
		{
			title:    "Top Depended-On Components",
			subtitle: "top",
			details:  topDependedOnDetails(m.graphValue),
		},
	}
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewOverview),
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Tab or 1-6 switches tabs; e export; ? help",
		emptyState:     "No scan overview is available.",
		items:          items,
	}
}

func (m *scanModel) buildVulnsListModel() *listModel {
	all := make([]sdk.Finding, 0, len(m.findings))
	for _, f := range m.findings {
		if f.Kind == sdk.FindingKindVulnerability {
			all = append(all, f)
		}
	}

	// Apply severity filter.
	filtered := all
	if m.severityFilter != "" {
		filtered = make([]sdk.Finding, 0, len(all))
		for _, f := range all {
			if strings.EqualFold(f.Severity, m.severityFilter) {
				filtered = append(filtered, f)
			}
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		ri, rj := severityRank(filtered[i].Severity), severityRank(filtered[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return filtered[i].ID < filtered[j].ID
	})

	items := make([]listItem, 0, len(filtered))
	for _, f := range filtered {
		pkgName := ""
		if f.Package != nil {
			pkgName = f.Package.Name
			if f.Package.Version != "" {
				pkgName += "@" + f.Package.Version
			}
		}
		// Append pkgName directly to the title so it renders as plain (white)
		// text without any background-color badge that causes contrast issues.
		titleStr := f.ID
		if pkgName != "" {
			titleStr += "  " + pkgName
		}
		items = append(items, listItem{
			title:  titleStr,
			badges: []badge{{label: f.Severity, kind: "severity-" + strings.ToLower(f.Severity)}},
			details: []string{
				render.Style("ID        ", render.Dim) + valueOrDash(f.ID),
				render.Style("Severity  ", render.Dim) + severityText(f.Severity),
				render.Style("Package   ", render.Dim) + valueOrDash(pkgName),
				render.Style("Title     ", render.Dim) + valueOrDash(f.Title),
				render.Style("Source    ", render.Dim) + valueOrDash(f.Source),
			},
		})
	}

	return &listModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: append(m.scanSummaryLines(interactiveScanViewVulns), []string{
			render.Style("Filter severity ", render.Dim) + valueOrDash(m.severityFilter),
			render.Style(fmt.Sprintf("Showing %d / %d", len(filtered), len(all)), render.Cyan, render.Bold),
		}...),
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; v cycles severity filter; 1-6 switch tabs",
		emptyState:     "No policy findings found. Run with --audit to evaluate enriched vulnerability data.",
		items:          items,
	}
}

func (m *scanModel) buildLicensesListModel() *listModel {
	rows := licenseRows(m.graphValue)
	items := make([]listItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, listItem{
			title:    row.license,
			subtitle: fmt.Sprintf("%d package(s)", len(row.packages)),
			details:  licenseDetails(row),
		})
	}

	return &listModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: append(m.scanSummaryLines(interactiveScanViewLicenses), []string{
			render.Style(fmt.Sprintf("Unique licenses %d", len(rows)), render.Cyan, render.Bold),
		}...),
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; 1-6 switch tabs",
		emptyState:     "No license information found.",
		items:          items,
	}
}

func (m *scanModel) buildFindingsListModel() *listModel {
	items := make([]listItem, 0, len(m.findings))
	for _, finding := range m.findings {
		pkg := ""
		if finding.Package != nil {
			pkg = packageDisplayName(finding.Package)
		}
		details := []string{
			render.Style("Finding", render.Bold, render.Cyan),
			render.Style("  ID: ", render.Dim) + valueOrDash(finding.ID),
			render.Style("  Kind: ", render.Dim) + valueOrDash(string(finding.Kind)),
			render.Style("  Severity: ", render.Dim) + severityText(finding.Severity),
			render.Style("  Package: ", render.Dim) + valueOrDash(pkg),
			render.Style("  Title: ", render.Dim) + valueOrDash(finding.Title),
			render.Style("  Source: ", render.Dim) + valueOrDash(finding.Source),
			"",
			render.Style("Reasons", render.Bold, render.Magenta),
		}
		details = append(details, indentLines(finding.Reasons)...)
		items = append(items, listItem{
			title:    finding.ID,
			subtitle: string(finding.Kind),
			badges:   []badge{{label: finding.Severity, kind: "severity-" + strings.ToLower(finding.Severity)}},
			details:  details,
		})
	}
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewFindings),
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; 1-6 switch tabs",
		emptyState:     "No findings found. Run with --audit to evaluate available vulnerability data.",
		items:          items,
	}
}

func (m *scanModel) buildSourceListModel() *listModel {
	items := []listItem{{
		title:    sourceTitle("root", "root"),
		subtitle: "source",
		details:  sourceRootDetails(m),
	}}
	if m.sourceExpanded["root"] {
		items = append(items, listItem{
			title:    sourceTitle("target", "  target"),
			subtitle: "node",
			details:  sourceTargetDetails(m),
		})
		items = append(items, listItem{
			title:    sourceTitle("manifests", fmt.Sprintf("  manifests (%d)", len(m.manifests))),
			subtitle: "node",
			details:  sourceManifestDetails(m),
		})
		items = append(items, listItem{
			title:    sourceTitle("packages", fmt.Sprintf("  packages (%d)", graphSize(m.graphValue))),
			subtitle: "node",
			details:  sourcePackageDetails(m.graphValue),
		})
		items = append(items, listItem{
			title:    sourceTitle("relationships", fmt.Sprintf("  relationships (%d)", relationshipCount(m.graphValue))),
			subtitle: "node",
			details:  sourceRelationshipDetails(m.graphValue),
		})
	}
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewSource),
		navigationHelp: interactiveCommonNavigationHelp + "; Enter expands/collapses source nodes",
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; 1-6 switch tabs; e export; ? help",
		emptyState:     "No source data is available.",
		items:          items,
	}
}

type licenseRow struct {
	license  string
	packages []licensePackageRef
}

type licensePackageRef struct {
	id          string
	displayName string
	version     string
	scope       string
}

func licenseRows(graphValue *sdk.Graph) []licenseRow {
	if graphValue == nil {
		return nil
	}

	rowsByLicense := make(map[string]map[string]licensePackageRef)
	for _, pkg := range graphValue.Packages() {
		if pkg == nil {
			continue
		}
		for _, licenseValue := range pkg.LicenseValues() {
			licenseValue = strings.TrimSpace(licenseValue)
			if licenseValue == "" {
				continue
			}
			packageRefs, ok := rowsByLicense[licenseValue]
			if !ok {
				packageRefs = make(map[string]licensePackageRef)
				rowsByLicense[licenseValue] = packageRefs
			}
			packageRefs[pkg.ID] = licensePackageRef{
				id:          pkg.ID,
				displayName: pkg.DisplayName(),
				version:     pkg.Version,
				scope:       pkg.Scope,
			}
		}
	}

	rows := make([]licenseRow, 0, len(rowsByLicense))
	for licenseValue, packageRefs := range rowsByLicense {
		packages := make([]licensePackageRef, 0, len(packageRefs))
		for _, pkg := range packageRefs {
			packages = append(packages, pkg)
		}
		sort.Slice(packages, func(i, j int) bool {
			if packages[i].displayName != packages[j].displayName {
				return packages[i].displayName < packages[j].displayName
			}
			if packages[i].version != packages[j].version {
				return packages[i].version < packages[j].version
			}
			return packages[i].id < packages[j].id
		})
		rows = append(rows, licenseRow{
			license:  licenseValue,
			packages: packages,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].license < rows[j].license
	})
	return rows
}

func licenseDetails(row licenseRow) []string {
	lines := []string{
		render.Style("License", render.Bold, render.Cyan),
		render.Style("  Identifier: ", render.Dim) + valueOrDash(row.license),
		render.Style("  Package count: ", render.Dim) + fmt.Sprintf("%d", len(row.packages)),
		"",
		render.Style("Packages Using This License", render.Bold, render.Magenta),
	}
	if len(row.packages) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
		return lines
	}
	for _, pkg := range row.packages {
		label := pkg.displayName
		if pkg.version != "" {
			label += "@" + pkg.version
		}
		if pkg.scope != "" {
			label += " [" + pkg.scope + "]"
		}
		lines = append(lines, render.Style("  - ", render.Dim)+label)
	}
	return lines
}

func (m *scanModel) buildComponentListModel(manifest listPackageRow) *listModel {
	if m.explainMode {
		return m.buildExplainComponentListModel(manifest)
	}
	rootPkg, _ := m.graphValue.Package(manifest.rootID)
	groups := rootDependencies(m.graphValue, manifest.rootID)

	// Build rows: root first, then direct, then transitive
	rows := make([]listPackageRow, 0, 1+len(groups.direct)+len(groups.transitive))

	// Add root package first
	if rootPkg != nil {
		rows = append(rows, packageRowFromGraph(rootPkg, "root"))
	}

	for _, pkg := range groups.direct {
		rows = append(rows, packageRowFromGraph(pkg, "direct"))
	}
	for _, pkg := range groups.transitive {
		rows = append(rows, packageRowFromGraph(pkg, "transitive"))
	}
	rows = filterPackageRows(rows, m.relationshipFilter, m.scopeFilter)

	// Compute highest severity per package for badge display, filtering, and sorting.
	maxSevByID := maxSeverityByPkgID(m.findings)

	// Apply severity filter.
	if m.severityFilter != "" {
		kept := rows[:0]
		for _, row := range rows {
			if strings.EqualFold(maxSevByID[row.id], m.severityFilter) {
				kept = append(kept, row)
			}
		}
		rows = kept
	}

	// Sort: highest severity first, then relationship, then ID.
	sort.Slice(rows, func(i, j int) bool {
		si := severityRank(maxSevByID[rows[i].id])
		sj := severityRank(maxSevByID[rows[j].id])
		if si != sj {
			return si < sj
		}
		if rows[i].relationship != rows[j].relationship {
			return render.RelationshipOrder(rows[i].relationship) < render.RelationshipOrder(rows[j].relationship)
		}
		return rows[i].id < rows[j].id
	})

	items := make([]listItem, 0, len(rows))
	for _, row := range rows {
		badges := packageBadges(row)
		if sev := maxSevByID[row.id]; sev != "" {
			// Prepend the severity badge so it appears before the scope badge.
			badges = append([]badge{{label: sev, kind: "severity-" + strings.ToLower(sev)}}, badges...)
		}
		items = append(items, listItem{
			title:    row.displayName,
			subtitle: row.relationship,
			badges:   badges,
			details:  componentDetails(m.graphValue, row, manifest, m.findings),
		})
	}

	navigationHelp := interactiveCommonNavigationHelp
	if m.allowManifestExit {
		navigationHelp += "; Backspace/Left/h returns to manifests"
	}

	return &listModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: append(m.scanSummaryLines(interactiveScanViewPackages), []string{
			render.Style("Manifest  ", render.Dim) + manifest.displayName,
			render.Style("Root      ", render.Dim) + packageDisplayName(rootPkg),
			render.Style("Filter relationship ", render.Dim) + valueOrDash(m.relationshipFilter),
			render.Style("Filter scope ", render.Dim) + valueOrDash(m.scopeFilter),
			render.Style("Filter severity ", render.Dim) + valueOrDash(m.severityFilter),
			render.Style(fmt.Sprintf("Direct    %d", len(groups.direct)), render.Cyan, render.Bold),
			render.Style(fmt.Sprintf("Transitive %d", len(groups.transitive)), render.Cyan, render.Bold),
			render.Style("Project   ", render.Dim) + m.project.Path,
		}...),
		navigationHelp: navigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; r relationship; s scope; v severity; 1-6 tabs",
		emptyState:     "No components were found for this manifest.",
		items:          items,
	}
}

func (m *scanModel) buildExplainComponentListModel(manifest listPackageRow) *listModel {
	labels, counts := explainRelationships(m.graphValue, manifest.targetID)
	rows := make([]listPackageRow, 0, len(labels))
	if m.graphValue != nil {
		for _, pkg := range m.graphValue.Packages() {
			if pkg == nil {
				continue
			}
			row := packageRowFromGraph(pkg, labels[pkg.ID])
			row.targetID = manifest.targetID
			rows = append(rows, row)
		}
	}
	rows = filterPackageRows(rows, m.relationshipFilter, m.scopeFilter)
	maxSevByID := maxSeverityByPkgID(m.findings)
	if m.severityFilter != "" {
		kept := rows[:0]
		for _, row := range rows {
			if strings.EqualFold(maxSevByID[row.id], m.severityFilter) {
				kept = append(kept, row)
			}
		}
		rows = kept
	}
	sort.Slice(rows, func(i, j int) bool {
		si := severityRank(maxSevByID[rows[i].id])
		sj := severityRank(maxSevByID[rows[j].id])
		if si != sj {
			return si < sj
		}
		if rows[i].relationship != rows[j].relationship {
			return render.RelationshipOrder(rows[i].relationship) < render.RelationshipOrder(rows[j].relationship)
		}
		return rows[i].id < rows[j].id
	})
	items := make([]listItem, 0, len(rows))
	for _, row := range rows {
		badges := packageBadges(row)
		if sev := maxSevByID[row.id]; sev != "" {
			badges = append([]badge{{label: sev, kind: "severity-" + strings.ToLower(sev)}}, badges...)
		}
		items = append(items, listItem{
			title:    row.displayName,
			subtitle: row.relationship,
			badges:   badges,
			details:  componentDetails(m.graphValue, row, manifest, m.findings),
		})
	}
	targetPkg, _ := m.graphValue.Package(manifest.targetID)
	return &listModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: append(m.scanSummaryLines(interactiveScanViewPackages), []string{
			render.Style("Manifest  ", render.Dim) + manifest.displayName,
			render.Style("Target    ", render.Dim) + packageDisplayName(targetPkg),
			render.Style("Filter relationship ", render.Dim) + valueOrDash(m.relationshipFilter),
			render.Style("Filter scope ", render.Dim) + valueOrDash(m.scopeFilter),
			render.Style("Filter severity ", render.Dim) + valueOrDash(m.severityFilter),
			render.Style(fmt.Sprintf("Self      %d", counts["self"]), render.Cyan, render.Bold),
			render.Style(fmt.Sprintf("Parents   %d", counts["parent"]), render.Cyan, render.Bold),
			render.Style(fmt.Sprintf("Ancestors %d", counts["ancestor"]), render.Cyan, render.Bold),
			render.Style(fmt.Sprintf("Roots     %d", counts["root"]), render.Cyan, render.Bold),
			render.Style("Project   ", render.Dim) + m.project.Path,
		}...),
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; r relationship; s scope; v severity; 1-6 tabs",
		emptyState:     "No components were found for this explanation.",
		items:          items,
	}
}

func manifestIDFromTitle(value string) string {
	start := strings.LastIndex(value, "[")
	end := strings.LastIndex(value, "]")
	if start == -1 || end == -1 || end <= start+1 {
		return ""
	}
	return strings.TrimSpace(value[start+1 : end])
}

func manifestRows(consolidated sdk.ConsolidatedGraph) []listPackageRow {
	if len(consolidated.Manifests) == 0 {
		return nil
	}

	rows := make([]listPackageRow, 0, len(consolidated.Manifests))
	for idx, manifest := range consolidated.Manifests {
		manifestID := strings.TrimSpace(manifest.Entry.Manifest.Path)
		if manifestID == "" {
			manifestID = fmt.Sprintf("manifest-%d", idx+1)
		}

		manifestName := filepath.Base(strings.ReplaceAll(manifestID, "\\", "/"))
		if manifestName == "" {
			manifestName = manifestID
		}

		rootID := ""
		if strings.TrimSpace(manifest.RootManifestID) != "" {
			rootID = manifest.RootManifestID
		} else if manifest.Entry.Graph != nil {
			roots := manifest.Entry.Graph.Roots()
			if len(roots) > 0 && roots[0] != nil {
				rootID = roots[0].ID
			}
		}

		rows = append(rows, listPackageRow{
			id:           manifestID,
			rootID:       rootID,
			targetID:     manifestTargetID(manifest.Entry.Graph),
			displayName:  manifestName,
			relationship: "manifest",
		})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	return rows
}

func manifestDetails(graphValue *sdk.Graph, row listPackageRow) []string {
	groups := rootDependencies(graphValue, row.rootID)
	rootPkg, _ := graphValue.Package(row.rootID)
	lines := []string{
		render.Style("Manifest", render.Bold, render.Cyan),
		render.Style("  Name: ", render.Dim) + row.displayName,
		render.Style("  ID: ", render.Dim) + valueOrDash(row.id),
		render.Style("  Kind: ", render.Dim) + valueOrDash(filepath.Base(row.id)),
		render.Style("  Type: ", render.Dim) + statusText(row.relationship),
		"",
		render.Style("Dependencies", render.Bold, render.Magenta),
		render.Style("  Root (project package): ", render.Dim) + packageDisplayName(rootPkg),
		render.Style("  Direct dependencies: ", render.Dim) + fmt.Sprintf("%d", len(groups.direct)),
		render.Style("  Transitive dependencies: ", render.Dim) + fmt.Sprintf("%d", len(groups.transitive)),
		"",
		render.Style("Press Enter to view components for this manifest.", render.Dim),
		"",
	}
	return lines
}

func manifestTargetID(graphValue *sdk.Graph) string {
	if graphValue == nil {
		return ""
	}
	leaves := make([]string, 0)
	for _, pkg := range graphValue.Packages() {
		if pkg == nil {
			continue
		}
		deps, err := graphValue.Dependencies(pkg.ID)
		if err == nil && len(deps) == 0 {
			leaves = append(leaves, pkg.ID)
		}
	}
	if len(leaves) == 0 {
		return ""
	}
	sort.Strings(leaves)
	return leaves[0]
}

func packageRowFromGraph(pkg *sdk.Package, relationship string) listPackageRow {
	if pkg == nil {
		return listPackageRow{relationship: relationship}
	}
	name := pkg.DisplayName()
	displayName := name
	if pkg.Version != "" {
		displayName = name + "@" + pkg.Version
	}
	return listPackageRow{
		id:           pkg.ID,
		rootID:       pkg.ID,
		displayName:  displayName,
		version:      pkg.Version,
		scope:        pkg.Scope,
		relationship: relationship,
		purl:         pkg.PURL,
	}
}

func packageDisplayName(pkg *sdk.Package) string {
	if pkg == nil {
		return "-"
	}
	name := pkg.DisplayName()
	if pkg.Version != "" {
		name += "@" + pkg.Version
	}
	if pkg.Scope != "" {
		name += " [" + pkg.Scope + "]"
	}
	return name
}

func componentBaseName(value string) string {
	if idx := strings.LastIndex(value, " ["); idx >= 0 && strings.HasSuffix(value, "]") {
		return value[:idx]
	}
	return value
}

func componentDetails(graphValue *sdk.Graph, row listPackageRow, manifest listPackageRow, findings []sdk.Finding) []string {
	lines := []string{
		render.Style("Component", render.Bold, render.Cyan),
		render.Style("  Manifest: ", render.Dim) + manifest.displayName,
		render.Style("  Name: ", render.Dim) + componentBaseName(row.displayName),
		render.Style("  ID: ", render.Dim) + valueOrDash(row.id),
		render.Style("  Version: ", render.Dim) + valueOrDash(row.version),
		render.Style("  Scope: ", render.Dim) + valueOrDash(row.scope),
		render.Style("  Relationship: ", render.Dim) + statusText(row.relationship),
		render.Style("  PURL: ", render.Dim) + valueOrDash(row.purl),
		"",
	}

	appendPackages := func(title string, packages []*sdk.Package) {
		lines = append(lines, render.Style(title, render.Bold, render.Magenta))
		if len(packages) == 0 {
			lines = append(lines, render.Style("  (none)", render.Dim))
			lines = append(lines, "")
			return
		}
		for _, pkg := range packages {
			value := pkg.DisplayName()
			if pkg.Version != "" {
				value += "@" + pkg.Version
			}
			if pkg.Scope != "" {
				value += " [" + pkg.Scope + "]"
			}
			lines = append(lines, render.Style("  - ", render.Dim)+value)
		}
		lines = append(lines, "")
	}

	if graphValue != nil {
		deps, _ := graphValue.Dependencies(row.id)
		appendPackages("Dependencies", deps)
		dependents, _ := graphValue.Dependents(row.id)
		appendPackages("Dependents", dependents)
	}

	// Vulnerabilities section
	lines = append(lines, render.Style("Vulnerabilities", render.Bold, render.Cyan))
	var pkgFindings []sdk.Finding
	for _, f := range findings {
		if f.Kind == sdk.FindingKindVulnerability && f.Package != nil && f.Package.ID == row.id {
			pkgFindings = append(pkgFindings, f)
		}
	}
	if len(pkgFindings) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, f := range pkgFindings {
			var severityLabel string
			switch strings.ToLower(f.Severity) {
			case "critical":
				severityLabel = render.Style(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", render.BgRed, render.White, render.Bold)
			case "high":
				severityLabel = render.Style(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", render.BgRed, render.White)
			case "medium":
				severityLabel = render.Style(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", render.BgYellow, render.Bold)
			case "low":
				severityLabel = render.Style(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", render.BgCyan, render.Blue, render.Bold)
			default:
				severityLabel = render.Style(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", render.Dim)
			}
			title := valueOrDash(f.Title)
			if title == "-" {
				title = ""
			} else {
				title = " " + title
			}
			lines = append(lines, "  "+severityLabel+" "+render.Style(f.ID, render.Bold)+title)
		}
	}
	lines = append(lines, "")

	// Licenses section
	lines = append(lines, render.Style("Licenses", render.Bold, render.Cyan))
	var pkg *sdk.Package
	if graphValue != nil {
		pkg, _ = graphValue.Package(row.id)
	}
	if pkg == nil || len(pkg.Licenses) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, lic := range pkg.Licenses {
			expr := lic.SPDXExpression
			if expr == "" {
				expr = lic.Value
			}
			if lic.Type != "" {
				expr += " [" + lic.Type + "]"
			}
			lines = append(lines, render.Style("  - ", render.Dim)+valueOrDash(expr))
		}
	}
	lines = append(lines, "")

	return lines
}

type scanOverviewStats struct {
	components      int
	vulnerabilities int
	licenses        int
	ecosystems      map[string]int
}

func scanStats(graphValue *sdk.Graph, findings []sdk.Finding) scanOverviewStats {
	stats := scanOverviewStats{ecosystems: make(map[string]int)}
	licenseSet := make(map[string]struct{})
	if graphValue != nil {
		stats.components = graphValue.Size()
		for _, pkg := range graphValue.Packages() {
			if pkg == nil {
				continue
			}
			if pkg.Ecosystem != "" {
				stats.ecosystems[pkg.Ecosystem]++
			} else {
				stats.ecosystems["unknown"]++
			}
			for _, licenseValue := range pkg.LicenseValues() {
				licenseSet[licenseValue] = struct{}{}
			}
			stats.vulnerabilities += len(pkg.Vulnerabilities)
		}
	}
	for _, finding := range findings {
		if finding.Kind == sdk.FindingKindVulnerability && stats.vulnerabilities == 0 {
			stats.vulnerabilities++
		}
	}
	stats.licenses = len(licenseSet)
	return stats
}

func severityDistribution(findings []sdk.Finding) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
	for _, finding := range findings {
		sev := strings.ToLower(strings.TrimSpace(finding.Severity))
		if _, ok := counts[sev]; !ok {
			sev = "unknown"
		}
		counts[sev]++
	}
	return counts
}

func distributionDetails(title string, counts map[string]int) []string {
	lines := []string{render.Style(title, render.Bold, render.Cyan)}
	for _, key := range sortedCountKeys(counts) {
		lines = append(lines, render.Style("  "+key+": ", render.Dim)+barLine(counts[key], maxCount(counts)))
	}
	if len(lines) == 1 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	}
	return lines
}

func licenseDistributionDetails(graphValue *sdk.Graph) []string {
	counts := make(map[string]int)
	for _, row := range licenseRows(graphValue) {
		counts[row.license] = len(row.packages)
	}
	return distributionDetails("License Distribution", counts)
}

func topVulnerableComponentDetails(findings []sdk.Finding) []string {
	counts := make(map[string]int)
	for _, finding := range findings {
		if finding.Package == nil {
			continue
		}
		counts[packageDisplayName(finding.Package)]++
	}
	return distributionDetails("Top Vulnerable Components", topCounts(counts, 10))
}

func topDependedOnDetails(graphValue *sdk.Graph) []string {
	counts := make(map[string]int)
	if graphValue != nil {
		for _, pkg := range graphValue.Packages() {
			if pkg == nil {
				continue
			}
			dependents, err := graphValue.Dependents(pkg.ID)
			if err == nil && len(dependents) > 0 {
				counts[packageDisplayName(pkg)] = len(dependents)
			}
		}
	}
	return distributionDetails("Top Depended-On Components", topCounts(counts, 10))
}

func topCounts(counts map[string]int, limit int) map[string]int {
	keys := sortedCountKeys(counts)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	out := make(map[string]int, len(keys))
	for _, key := range keys {
		out[key] = counts[key]
	}
	return out
}

func sortedCountKeys(counts map[string]int) []string {
	keys := make([]string, 0, len(counts))
	for key, value := range counts {
		if value == 0 {
			continue
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

func maxCount(counts map[string]int) int {
	max := 0
	for _, value := range counts {
		if value > max {
			max = value
		}
	}
	return max
}

func barLine(value, max int) string {
	width := 18
	filled := 0
	if max > 0 {
		filled = value * width / max
		if value > 0 && filled == 0 {
			filled = 1
		}
	}
	return render.Style(strings.Repeat("=", filled), render.Green) + render.Style(strings.Repeat(".", width-filled), render.Dim) + fmt.Sprintf(" %d", value)
}

func sourceTitle(key, label string) string {
	return label + " [" + key + "]"
}

func sourceKey(title string) string {
	start := strings.LastIndex(title, "[")
	end := strings.LastIndex(title, "]")
	if start == -1 || end <= start+1 {
		return ""
	}
	return strings.TrimSpace(title[start+1 : end])
}

func sourceRootDetails(m *scanModel) []string {
	return []string{
		render.Style("SBOM Source Map", render.Bold, render.Cyan),
		render.Style("  Target: ", render.Dim) + valueOrDash(m.project.Name),
		render.Style("  Packages: ", render.Dim) + fmt.Sprintf("%d", graphSize(m.graphValue)),
		render.Style("  Relationships: ", render.Dim) + fmt.Sprintf("%d", relationshipCount(m.graphValue)),
		render.Style("  Manifests: ", render.Dim) + fmt.Sprintf("%d", len(m.manifests)),
		"",
		render.Style("Press Enter to expand or collapse source nodes.", render.Dim),
	}
}

func sourceTargetDetails(m *scanModel) []string {
	return []string{
		render.Style("Target", render.Bold, render.Cyan),
		render.Style("  Name: ", render.Dim) + valueOrDash(m.project.Name),
		render.Style("  Path: ", render.Dim) + valueOrDash(m.project.Path),
		render.Style("  Ecosystem: ", render.Dim) + valueOrDash(m.project.Ecosystem),
		render.Style("  Package manager: ", render.Dim) + valueOrDash(m.project.PackageManager),
	}
}

func sourceManifestDetails(m *scanModel) []string {
	lines := []string{render.Style("Manifests", render.Bold, render.Cyan)}
	for _, manifest := range m.manifests {
		lines = append(lines, render.Style("  - ", render.Dim)+manifest.id)
	}
	if len(lines) == 1 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	}
	return lines
}

func sourcePackageDetails(graphValue *sdk.Graph) []string {
	lines := []string{render.Style("Packages", render.Bold, render.Cyan)}
	if graphValue != nil {
		for _, pkg := range graphValue.Packages() {
			lines = append(lines, render.Style("  - ", render.Dim)+packageDisplayName(pkg))
			if len(lines) >= 32 {
				lines = append(lines, render.Style("  ...", render.Dim))
				break
			}
		}
	}
	if len(lines) == 1 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	}
	return lines
}

func sourceRelationshipDetails(graphValue *sdk.Graph) []string {
	lines := []string{render.Style("Relationships", render.Bold, render.Cyan)}
	if graphValue != nil {
		graphValue.WalkRelationships(func(from, to *sdk.Package) bool {
			lines = append(lines, render.Style("  - ", render.Dim)+packageDisplayName(from)+" -> "+packageDisplayName(to))
			return len(lines) < 32
		})
	}
	if len(lines) == 1 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	}
	return lines
}

func graphSize(graphValue *sdk.Graph) int {
	if graphValue == nil {
		return 0
	}
	return graphValue.Size()
}

func relationshipCount(graphValue *sdk.Graph) int {
	count := 0
	if graphValue != nil {
		graphValue.WalkRelationships(func(_, _ *sdk.Package) bool {
			count++
			return true
		})
	}
	return count
}

func indentLines(values []string) []string {
	if len(values) == 0 {
		return []string{render.Style("  (none)", render.Dim)}
	}
	lines := make([]string, 0, len(values))
	for _, value := range values {
		lines = append(lines, render.Style("  - ", render.Dim)+value)
	}
	return lines
}

func targetKindLabel(project output.ProjectDescriptor) string {
	switch {
	case project.PackageManager != "":
		return project.PackageManager
	case project.Ecosystem != "":
		return project.Ecosystem
	default:
		return "dependency graph"
	}
}

func rootDependencies(graphValue *sdk.Graph, rootID string) rootDependencyGroup {
	if graphValue == nil || strings.TrimSpace(rootID) == "" {
		return rootDependencyGroup{}
	}

	direct, err := graphValue.Dependencies(rootID)
	if err != nil || len(direct) == 0 {
		return rootDependencyGroup{}
	}

	directByID := make(map[string]*sdk.Package, len(direct))
	for _, pkg := range direct {
		directByID[pkg.ID] = pkg
	}

	transitiveByID := make(map[string]*sdk.Package)
	visited := make(map[string]struct{}, len(direct)+1)
	queue := make([]string, 0, len(direct))
	visited[rootID] = struct{}{}
	for _, pkg := range direct {
		queue = append(queue, pkg.ID)
		visited[pkg.ID] = struct{}{}
	}

	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]
		dependencies, depErr := graphValue.Dependencies(currentID)
		if depErr != nil {
			continue
		}
		for _, dependency := range dependencies {
			if dependency == nil || dependency.ID == rootID {
				continue
			}
			if _, isDirect := directByID[dependency.ID]; !isDirect {
				if _, exists := transitiveByID[dependency.ID]; !exists {
					transitiveByID[dependency.ID] = dependency
				}
			}
			if _, seen := visited[dependency.ID]; seen {
				continue
			}
			visited[dependency.ID] = struct{}{}
			queue = append(queue, dependency.ID)
		}
	}

	transitive := make([]*sdk.Package, 0, len(transitiveByID))
	for _, pkg := range transitiveByID {
		transitive = append(transitive, pkg)
	}
	sort.Slice(direct, func(i, j int) bool {
		return packageSortKey(direct[i]) < packageSortKey(direct[j])
	})
	sort.Slice(transitive, func(i, j int) bool {
		return packageSortKey(transitive[i]) < packageSortKey(transitive[j])
	})

	return rootDependencyGroup{direct: direct, transitive: transitive}
}

func packageSortKey(pkg *sdk.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.ID + "\x00" + pkg.DisplayName() + "\x00" + pkg.Version
}
