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
	return newScanNavigator(titlePrefix, project, consolidated, graphValue, findings, "")
}

func NewExplain(project output.ProjectDescriptor, query string, consolidated sdk.ConsolidatedGraph, graphValue *sdk.Graph, findings []sdk.Finding) *scanModel {
	return newScanNavigator("Bomly Interactive Explain", project, consolidated, graphValue, findings, query)
}

func newScanNavigator(titlePrefix string, project output.ProjectDescriptor, consolidated sdk.ConsolidatedGraph, graphValue *sdk.Graph, findings []sdk.Finding, explainQuery string) *scanModel {
	manifests := manifestRows(consolidated)
	manifestByID := make(map[string]listPackageRow, len(manifests))
	for _, manifest := range manifests {
		manifestByID[manifest.id] = manifest
	}

	model := &scanModel{
		titlePrefix:           titlePrefix,
		project:               project,
		graphValue:            graphValue,
		explainMode:           strings.Contains(strings.ToLower(titlePrefix), "explain"),
		manifests:             manifests,
		manifestByID:          manifestByID,
		mode:                  interactiveScanModeManifests,
		allowManifestExit:     len(manifests) > 1,
		findings:              findings,
		activeView:            interactiveScanViewOverview,
		explainQuery:          strings.TrimSpace(explainQuery),
		sourceExpanded:        map[string]bool{"root": true},
		componentExpanded:     map[string]bool{},
		vulnerabilityGroup:    "component",
		vulnerabilityExpanded: map[string]bool{},
		licenseGroup:          "license",
		licenseExpanded:       map[string]bool{},
		findingGroup:          "type",
		findingExpanded:       map[string]bool{},
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
	if m.activeView == interactiveScanViewOverview && !m.IsSearching() {
		return m.overviewDashboardView(width, height)
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
	m.toggleSelectedTreeNode()
}

func (m *scanModel) toggleSelectedTreeNode() {
	if m == nil || m.list == nil {
		return
	}
	visible := m.list.visibleItemIndices()
	if len(visible) == 0 {
		return
	}
	item := m.list.items[visible[m.list.selectedVisibleIndex(visible)]]
	if m.activeView == interactiveScanViewPackages && item.canOpen && item.key != "" {
		m.componentExpanded[item.key] = !item.expanded
		m.rebuildListPreserveSelection()
		return
	}
	if m.activeView == interactiveScanViewVulns && item.canOpen && item.key != "" {
		m.vulnerabilityExpanded[item.key] = !item.expanded
		m.rebuildListPreserveSelection()
		return
	}
	if m.activeView == interactiveScanViewLicenses && item.canOpen && item.key != "" {
		m.licenseExpanded[item.key] = !item.expanded
		m.rebuildListPreserveSelection()
		return
	}
	if m.activeView == interactiveScanViewFindings && item.canOpen && item.key != "" {
		m.findingExpanded[item.key] = !item.expanded
		m.rebuildListPreserveSelection()
		return
	}
	if m.activeView != interactiveScanViewSource {
		return
	}
	if !item.canOpen {
		return
	}
	key := item.key
	if key == "" {
		key = sourceKey(item.title)
	}
	m.sourceExpanded[key] = !m.sourceExpanded[key]
	m.rebuildListPreserveSelection()
}

func (m *scanModel) ExpandSelected() {
	m.setSelectedTreeNode(true)
}

func (m *scanModel) CollapseSelected() {
	m.setSelectedTreeNode(false)
}

func (m *scanModel) setSelectedTreeNode(expanded bool) {
	if m == nil || m.list == nil {
		return
	}
	visible := m.list.visibleItemIndices()
	if len(visible) == 0 {
		return
	}
	item := m.list.items[visible[m.list.selectedVisibleIndex(visible)]]
	if !item.canOpen || item.key == "" || item.expanded == expanded {
		return
	}
	switch m.activeView {
	case interactiveScanViewPackages:
		m.componentExpanded[item.key] = expanded
	case interactiveScanViewVulns:
		m.vulnerabilityExpanded[item.key] = expanded
	case interactiveScanViewLicenses:
		m.licenseExpanded[item.key] = expanded
	case interactiveScanViewFindings:
		m.findingExpanded[item.key] = expanded
	case interactiveScanViewSource:
		m.sourceExpanded[item.key] = expanded
	default:
		return
	}
	m.rebuildListPreserveSelection()
}

func (m *scanModel) ExpandAll() {
	m.setAllTreeNodes(true)
}

func (m *scanModel) CollapseAll() {
	m.setAllTreeNodes(false)
}

func (m *scanModel) setAllTreeNodes(expanded bool) {
	if m == nil || m.list == nil {
		return
	}
	for _, item := range m.list.items {
		if !item.canOpen || item.key == "" {
			continue
		}
		switch m.activeView {
		case interactiveScanViewPackages:
			m.componentExpanded[item.key] = expanded
		case interactiveScanViewVulns:
			m.vulnerabilityExpanded[item.key] = expanded
		case interactiveScanViewLicenses:
			m.licenseExpanded[item.key] = expanded
		case interactiveScanViewFindings:
			m.findingExpanded[item.key] = expanded
		case interactiveScanViewSource:
			m.sourceExpanded[item.key] = expanded
		}
	}
	if m.activeView == interactiveScanViewPackages {
		m.componentExpanded["project"] = expanded
		for _, manifest := range m.manifests {
			m.componentExpanded["manifest:"+manifest.id] = expanded
		}
		if m.graphValue != nil {
			for _, pkg := range m.graphValue.Packages() {
				if pkg != nil {
					m.componentExpanded[pkg.ID] = expanded
				}
			}
		}
	}
	if m.activeView == interactiveScanViewSource {
		for _, key := range []string{"root", "target", "manifests", "packages", "relationships"} {
			m.sourceExpanded[key] = expanded
		}
		if m.graphValue != nil {
			for _, pkg := range m.graphValue.Packages() {
				if pkg != nil {
					m.sourceExpanded["package:"+pkg.ID] = expanded
				}
			}
		}
	}
	m.rebuildListPreserveSelection()
}

func (m *scanModel) CycleGroup() {
	if m == nil {
		return
	}
	switch m.activeView {
	case interactiveScanViewVulns:
		m.vulnerabilityGroup = nextFilterValue(m.vulnerabilityGroup, []string{"component", "severity", "ecosystem"})
	case interactiveScanViewLicenses:
		m.licenseGroup = nextFilterValue(m.licenseGroup, []string{"license", "category", "recognition"})
	case interactiveScanViewFindings:
		m.findingGroup = nextFilterValue(m.findingGroup, []string{"type", "severity", "component", "ecosystem"})
	default:
		return
	}
	m.rebuildListPreserveSelection()
}

func (m *scanModel) CycleRelationshipFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages {
		return
	}
	m.relationshipFilter = nextRelationshipFilter(m.relationshipFilter, m.explainMode)
	m.rebuildListPreserveSelection()
}

func (m *scanModel) CycleScopeFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages {
		return
	}
	m.scopeFilter = nextScopeFilter(m.scopeFilter)
	m.rebuildListPreserveSelection()
}

func (m *scanModel) CycleSeverityFilter() {
	if m == nil {
		return
	}
	switch m.activeView {
	case interactiveScanViewVulns:
		// always applicable
	case interactiveScanViewPackages:
	default:
		return
	}
	m.severityFilter = nextSeverityFilter(m.severityFilter)
	m.rebuildListPreserveSelection()
}

func (m *scanModel) CycleEcosystemFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages {
		return
	}
	m.ecosystemFilter = nextFilterValue(m.ecosystemFilter, append([]string{""}, m.componentEcosystemValues()...))
	m.rebuildListPreserveSelection()
}

func (m *scanModel) componentEcosystemValues() []string {
	if m == nil || m.graphValue == nil {
		return nil
	}
	values := make(map[string]struct{})
	for _, pkg := range m.graphValue.Packages() {
		if pkg == nil {
			continue
		}
		values[valueOrDefault(pkg.Ecosystem, "unknown")] = struct{}{}
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (m *scanModel) OpenSelected() {
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
	var list *listModel
	switch m.activeView {
	case interactiveScanViewOverview:
		list = m.buildOverviewListModel()
	case interactiveScanViewVulns:
		list = m.buildVulnsListModel()
	case interactiveScanViewLicenses:
		list = m.buildLicensesListModel()
	case interactiveScanViewFindings:
		list = m.buildFindingsListModel()
	case interactiveScanViewSource:
		list = m.buildSourceListModel()
	default:
		list = m.buildComponentsTreeListModel()
	}
	return m.withScanFooter(list)
}

func (m *scanModel) rebuildListPreserveSelection() {
	if m == nil {
		return
	}
	key, title, scrollOffset, detailOffset := "", "", 0, 0
	if m.list != nil {
		visible := m.list.visibleItemIndices()
		if len(visible) > 0 {
			item := m.list.items[visible[m.list.selectedVisibleIndex(visible)]]
			key = item.key
			title = item.title
		}
		scrollOffset = m.list.scrollOffset
		detailOffset = m.list.detailOffset
	}
	next := m.buildCurrentListModel()
	if next == nil {
		m.list = nil
		return
	}
	next.scrollOffset = scrollOffset
	next.detailOffset = detailOffset
	if key != "" || title != "" {
		for idx, item := range next.items {
			if (key != "" && item.key == key) || (key == "" && title != "" && item.title == title) {
				next.selected = idx
				break
			}
		}
	}
	m.list = next
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
	targetParts := []string{
		render.Style(valueOrDash(m.project.Name), render.White, render.Bold),
		render.Style(targetKindLabel(m.project), render.Dim),
	}
	if m.explainMode && m.explainQuery != "" {
		targetParts = append(targetParts, render.Style("package: "+m.explainQuery, render.Cyan, render.Bold))
	}
	if strings.TrimSpace(m.project.TargetRef) != "" {
		targetParts = append(targetParts, render.Style("ref: "+m.project.TargetRef, render.Cyan, render.Bold))
	}
	return []string{
		render.Style(" bomly ", render.BgCyan, render.Blue, render.Bold) + " " +
			render.Style(m.commandLabel(), render.BgBlue, render.White, render.Bold) + " " +
			strings.Join(targetParts, render.Style(" | ", render.Dim)),
		"",
		m.tabLine(active),
		"",
	}
}

func (m *scanModel) commandLabel() string {
	lower := strings.ToLower(m.titlePrefix)
	switch {
	case strings.Contains(lower, "explain"):
		return "EXPLAIN"
	case strings.Contains(lower, "diff"):
		return "DIFF"
	default:
		return "SCAN"
	}
}

func (m *scanModel) tabLine(active scanView) string {
	labels := []struct {
		view  scanView
		label string
	}{
		{interactiveScanViewOverview, "Overview"},
		{interactiveScanViewPackages, "Components"},
		{interactiveScanViewVulns, "Vulnerabilities"},
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

func (m *scanModel) scanFooterSummary() string {
	stats := scanStats(m.graphValue, m.findings)
	return fmt.Sprintf("Components: %d | Vulns: %d | Licenses: %d | Findings: %d", stats.components, stats.vulnerabilities, stats.licenses, len(m.findings))
}

func (m *scanModel) scanLegend() string {
	return strings.Join([]string{
		keyHint("Tab", "switch"),
		keyHint("Enter", "select"),
		keyHint("→", "expand"),
		keyHint("←", "collapse"),
		keyHint("]", "expand all"),
		keyHint("[", "collapse all"),
		keyHint("↑/↓", "move"),
		keyHint("q", "quit"),
	}, " ")
}

func (m *scanModel) scanFooterLines(width int) []string {
	return []string{
		statusBar(m.scanFooterSummary(), width),
		centerLine(m.scanLegend(), width),
	}
}

func (m *scanModel) withScanFooter(list *listModel) *listModel {
	if list == nil {
		return nil
	}
	list.footerSummary = m.scanFooterSummary()
	list.legend = m.scanLegend()
	list.title = ""
	return list
}

func (m *scanModel) componentControlsLine() string {
	return keyHint("/", "search") + " " + keyHint("r", "relationship") + " " + keyHint("s", "scope") + " " + keyHint("v", "severity") + " " + keyHint("e", "ecosystem") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all")
}

func (m *scanModel) componentStateLine(extra string) string {
	state := render.Style("Group: ", render.Dim) + render.Style("Dependency", render.BgYellow, render.Bold) +
		render.Style(" | Relationship: ", render.Dim) + render.Style(valueOrDefault(m.relationshipFilter, "All"), render.BgYellow, render.Bold) +
		render.Style(" | Scope: ", render.Dim) + render.Style(valueOrDefault(m.scopeFilter, "All"), render.BgYellow, render.Bold) +
		render.Style(" | Severity: ", render.Dim) + render.Style(valueOrDefault(m.severityFilter, "All"), render.BgYellow, render.Bold) +
		render.Style(" | Ecosystem: ", render.Dim) + render.Style(valueOrDefault(m.ecosystemFilter, "All"), render.BgYellow, render.Bold)
	if strings.TrimSpace(extra) != "" {
		state += render.Style(" | ", render.Dim) + extra
	}
	return state
}

func (m *scanModel) buildManifestListModel() *listModel {
	items := make([]listItem, 0, len(m.manifests)+1)
	items = append(items, listItem{
		title:    fmt.Sprintf("%s (%d manifests)", valueOrDash(m.project.Name), len(m.manifests)),
		subtitle: "project",
		details:  projectDetails(m, packageCount(m.graphValue), packageCount(m.graphValue)),
		key:      "project",
		canOpen:  true,
		expanded: true,
	})
	for idx, manifest := range m.manifests {
		title := fmt.Sprintf("%s (%s, %d components) [%s]", manifest.displayName, manifestEcosystem(m.graphValue, manifest), manifestComponentCount(m.graphValue, manifest.rootID), manifest.id)
		tree := "├─ "
		if idx == len(m.manifests)-1 {
			tree = "└─ "
		}
		items = append(items, listItem{
			title:    title,
			subtitle: "manifest",
			details:  manifestDetails(m.graphValue, manifest),
			tree:     tree,
			depth:    1,
		})
	}

	packageCount := 0
	if m.graphValue != nil {
		packageCount = m.graphValue.Size()
	}

	selected := 0
	if len(items) > 1 {
		selected = 1
	}
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewPackages),
		controls:       []string{m.componentControlsLine() + render.Style(" | Components: ", render.Dim) + fmt.Sprintf("%d", packageCount)},
		listTitle:      fmt.Sprintf("Manifests (%d)", len(m.manifests)),
		detailTitle:    "Manifest Details",
		navigationHelp: interactiveCommonNavigationHelp + "; Enter opens selected manifest",
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; 1-6 switch tabs",
		emptyState:     "No manifests were found in the dependency graph.",
		items:          items,
		selected:       selected,
	}
}

func (m *scanModel) buildComponentsTreeListModel() *listModel {
	totalComponents := packageCount(m.graphValue)
	maxSevByID := maxSeverityByPkgID(m.findings)
	filteredComponentCount := m.filteredComponentCount(maxSevByID)
	items := make([]listItem, 0, totalComponents+len(m.manifests)+1)
	projectKey := "project"
	projectExpanded := expandedValue(m.componentExpanded, projectKey, true)
	items = append(items, listItem{
		title:    fmt.Sprintf("%s (%d manifests)", valueOrDash(m.project.Name), len(m.manifests)),
		subtitle: "project",
		details:  projectDetails(m, filteredComponentCount, totalComponents),
		key:      projectKey,
		canOpen:  len(m.manifests) > 0,
		expanded: projectExpanded,
	})
	if projectExpanded {
		for idx, manifest := range m.manifests {
			manifestLast := idx == len(m.manifests)-1
			manifestKey := "manifest:" + manifest.id
			manifestExpanded := expandedValue(m.componentExpanded, manifestKey, true)
			manifestTree := "├─ "
			if manifestLast {
				manifestTree = "└─ "
			}
			items = append(items, listItem{
				title:    fmt.Sprintf("%s (%s, %d components)", manifest.displayName, manifestEcosystem(m.graphValue, manifest), m.filteredManifestComponentCount(manifest.rootID, maxSevByID)),
				subtitle: "manifest",
				details:  manifestDetails(m.graphValue, manifest),
				key:      manifestKey,
				tree:     manifestTree,
				depth:    1,
				canOpen:  manifest.rootID != "",
				expanded: manifestExpanded,
			})
			if !manifestExpanded {
				continue
			}
			rows := m.componentTreeRows(manifest.rootID)
			rows = m.filterComponentRows(rows, maxSevByID)
			for _, row := range rows {
				badges := packageBadges(row)
				if sev := maxSevByID[row.id]; sev != "" {
					badges = append([]badge{{label: sev, kind: "severity-" + strings.ToLower(sev)}}, badges...)
				}
				deps, _ := m.graphValue.Dependencies(row.id)
				expanded := expandedValue(m.componentExpanded, row.id, row.relationship == "root")
				if row.repeated {
					deps = nil
					expanded = false
				}
				items = append(items, listItem{
					title:    row.displayName,
					subtitle: row.relationship,
					badges:   badges,
					details:  componentDetails(m.graphValue, row, manifest, m.findings),
					key:      row.id,
					tree:     componentForestPrefix(manifestLast, row),
					depth:    row.depth + 2,
					canOpen:  len(deps) > 0,
					expanded: expanded,
				})
			}
		}
	}
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewPackages),
		controls:       []string{m.componentControlsLine(), m.componentStateLine(fmt.Sprintf("Components: %d of %d", filteredComponentCount, totalComponents))},
		listTitle:      fmt.Sprintf("Components (%d)", filteredComponentCount),
		detailTitle:    "Component Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter/Right/Left expands and collapses; r relationship; s scope; v severity; 1-6 tabs",
		emptyState:     "No components were found.",
		items:          items,
	}
}

func expandedValue(values map[string]bool, key string, defaultValue bool) bool {
	if value, ok := values[key]; ok {
		return value
	}
	return defaultValue
}

func componentForestPrefix(manifestLast bool, row listPackageRow) string {
	manifestPrefix := "│  "
	if manifestLast {
		manifestPrefix = "   "
	}
	if row.depth == 0 {
		return manifestPrefix + "└─ "
	}
	return manifestPrefix + "   " + row.tree
}

func projectDetails(m *scanModel, filteredComponents, totalComponents int) []string {
	return []string{
		render.Style("Project", render.Bold, render.Cyan),
		"",
		render.Style("  Name: ", render.Dim) + valueOrDash(m.project.Name),
		render.Style("  Path: ", render.Dim) + valueOrDash(m.project.Path),
		render.Style("  Type: ", render.Dim) + targetKindLabel(m.project),
		render.Style("  Manifests: ", render.Dim) + fmt.Sprintf("%d", len(m.manifests)),
		render.Style("  Components: ", render.Dim) + fmt.Sprintf("%d of %d", filteredComponents, totalComponents),
	}
}

func packageCount(graphValue *sdk.Graph) int {
	if graphValue == nil {
		return 0
	}
	return graphValue.Size()
}

func manifestComponentCount(graphValue *sdk.Graph, rootID string) int {
	if graphValue == nil || rootID == "" {
		return 0
	}
	rows := rootDependencies(graphValue, rootID)
	count := 0
	if _, ok := graphValue.Package(rootID); ok {
		count = 1
	}
	return count + len(rows.direct) + len(rows.transitive)
}

func (m *scanModel) filteredComponentCount(maxSevByID map[string]string) int {
	if m == nil {
		return 0
	}
	seen := make(map[string]struct{})
	for _, manifest := range m.manifests {
		for _, row := range m.filteredManifestComponentRows(manifest.rootID, maxSevByID) {
			seen[row.id] = struct{}{}
		}
	}
	return len(seen)
}

func (m *scanModel) filteredManifestComponentCount(rootID string, maxSevByID map[string]string) int {
	return len(m.filteredManifestComponentRows(rootID, maxSevByID))
}

func (m *scanModel) filteredManifestComponentRows(rootID string, maxSevByID map[string]string) []listPackageRow {
	if m == nil || m.graphValue == nil || rootID == "" {
		return nil
	}
	rows := componentCountRows(m.graphValue, rootID)
	return m.filterComponentRows(rows, maxSevByID)
}

func (m *scanModel) filterComponentRows(rows []listPackageRow, maxSevByID map[string]string) []listPackageRow {
	rows = filterPackageRows(rows, m.relationshipFilter, m.scopeFilter)
	if m.ecosystemFilter != "" {
		kept := rows[:0]
		for _, row := range rows {
			if strings.EqualFold(valueOrDefault(row.ecosystem, "unknown"), m.ecosystemFilter) {
				kept = append(kept, row)
			}
		}
		rows = kept
	}
	if m.severityFilter == "" {
		return rows
	}
	kept := rows[:0]
	for _, row := range rows {
		if strings.EqualFold(maxSevByID[row.id], m.severityFilter) {
			kept = append(kept, row)
		}
	}
	return kept
}

func componentCountRows(graphValue *sdk.Graph, rootID string) []listPackageRow {
	if graphValue == nil || strings.TrimSpace(rootID) == "" {
		return nil
	}
	rootPkg, ok := graphValue.Package(rootID)
	if !ok || rootPkg == nil {
		return nil
	}
	rows := []listPackageRow{packageRowFromGraph(rootPkg, "root")}
	groups := rootDependencies(graphValue, rootID)
	for _, pkg := range groups.direct {
		if pkg != nil {
			rows = append(rows, packageRowFromGraph(pkg, "direct"))
		}
	}
	for _, pkg := range groups.transitive {
		if pkg != nil {
			rows = append(rows, packageRowFromGraph(pkg, "transitive"))
		}
	}
	return rows
}

func manifestEcosystem(graphValue *sdk.Graph, row listPackageRow) string {
	if graphValue == nil {
		return "unknown"
	}
	pkg, ok := graphValue.Package(row.rootID)
	if !ok || pkg == nil {
		return "unknown"
	}
	return valueOrDefault(pkg.Ecosystem, "unknown")
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

func (m *scanModel) overviewDashboardView(width, height int) string {
	if width < 80 || height < 22 {
		return m.list.View(width, height)
	}
	var lines []string
	for _, summaryLine := range m.scanSummaryLines(interactiveScanViewOverview) {
		lines = append(lines, truncateToWidth(summaryLine, width))
	}
	footerLines := m.scanFooterLines(width)
	bodyHeight := height - len(lines) - len(footerLines)
	if bodyHeight < 12 {
		return m.list.View(width, height)
	}

	stats := scanStats(m.graphValue, m.findings)
	cardHeight := 9
	gap := 1
	leftHalf := (width - gap) / 2
	summaryWidth := (leftHalf - 2*gap) / 3
	targetWidth := width - leftHalf - gap
	cards := [][]string{
		boxView("Components", summaryCountCardLines(stats.components, "Components", summaryWidth-2, render.Cyan,
			fmt.Sprintf("%d ecosystems", len(stats.ecosystems)),
			fmt.Sprintf("%d manifests", len(m.manifests)),
		), summaryWidth, cardHeight, render.Cyan),
		boxView("Vulnerabilities", summaryCountCardLines(stats.vulnerabilities, "Vulnerabilities", summaryWidth-2, render.Red,
			severityCardLine(m.findings, "critical"),
			severityCardLine(m.findings, "high"),
			severityCardLine(m.findings, "medium"),
			severityCardLine(m.findings, "low"),
		), summaryWidth, cardHeight, render.Red),
		boxView("Licenses", summaryCountCardLines(stats.licenses, "Unique Licenses", summaryWidth-2, render.Yellow,
			fmt.Sprintf("%d unknown", unknownLicenseCount(m.graphValue)),
			fmt.Sprintf("%d unrecognized", unrecognizedLicenseCount(m.graphValue)),
		), summaryWidth, cardHeight, render.Yellow),
		boxView("Target", []string{
			render.Style("Name: ", render.Dim) + valueOrDash(m.project.Name),
			render.Style("Type: ", render.Dim) + targetKindLabel(m.project),
			render.Style("Ref: ", render.Dim) + valueOrDash(m.project.TargetRef),
			render.Style("Path: ", render.Dim) + valueOrDash(m.project.Path),
			render.Style("Ecosystem: ", render.Dim) + valueOrDash(m.project.Ecosystem),
			render.Style("Package manager: ", render.Dim) + valueOrDash(m.project.PackageManager),
			render.Style("Manifests: ", render.Dim) + fmt.Sprintf("%d", len(m.manifests)),
		}, targetWidth, cardHeight, render.Green),
	}
	for idx := 0; idx < cardHeight; idx++ {
		lines = append(lines, cards[0][idx]+" "+cards[1][idx]+" "+cards[2][idx]+" "+cards[3][idx])
	}
	lines = append(lines, "")

	remaining := bodyHeight - cardHeight - 1
	leftWidth := width / 2
	rightWidth := width - leftWidth - 1
	topVuln := topVulnerableComponentStats(m.graphValue, m.findings, 8)
	leftA := remaining / 3
	if leftA < 7 && remaining >= 14 {
		leftA = 7
	}
	leftB := (remaining - leftA - 2) / 2
	leftC := remaining - leftA - leftB - 2
	if leftC < 4 {
		leftC = 4
	}
	leftContent := stackBoxes(
		boxView("Ecosystem Distribution", coloredDistributionLines(stats.ecosystems, stats.components, 8, leftWidth-2), leftWidth, leftA, render.Cyan),
		boxView("Relationship Distribution", componentsByRelationshipLines(m.manifests, m.graphValue, leftWidth-2), leftWidth, leftB, render.Cyan),
		boxView("Scope Distribution", componentsByScopeLines(m.manifests, m.graphValue, leftWidth-2), leftWidth, leftC, render.Green),
	)
	rightA := remaining / 3
	if rightA < 6 && remaining >= 18 {
		rightA = 6
	}
	rightB := (remaining - rightA - 2) / 2
	rightC := remaining - rightA - rightB - 2
	if rightC < 4 {
		rightC = 4
	}
	rightContent := stackBoxes(
		boxView("License Distribution", coloredDistributionLines(groupedLicenseCounts(m.graphValue, 10), stats.components, 10, rightWidth-2), rightWidth, rightA, render.Yellow),
		boxView("Vulnerability Severity", severityDistributionLines(m.findings, rightWidth-2), rightWidth, rightB, render.Red),
		boxView(fmt.Sprintf("Top Vulnerable Components (%d)", vulnerableComponentTotal(m.graphValue, m.findings)), topVulnerableTableLines(topVuln, rightWidth-2), rightWidth, rightC, render.Red),
	)
	lines = append(lines, joinColumns(leftContent, rightContent, leftWidth, rightWidth)...)
	lines = append(lines, footerLines...)
	return strings.Join(lines, "\n")
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

	items := m.vulnerabilityItems(filtered)

	return &listModel{
		title:       fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:     m.scanSummaryLines(interactiveScanViewVulns),
		controls:    []string{m.vulnerabilityControlsLine(), m.vulnerabilityStateLine(len(filtered), len(all))},
		listTitle:   fmt.Sprintf("Vulnerabilities (%d)", len(filtered)),
		listHeader:  "Vulnerability ID / Group",
		detailTitle: "Vulnerability Details",
		topPanels: []listPanel{
			{title: "Severity Summary", lines: vulnerabilitySummaryLines(filtered), color: render.Red, weight: 1},
			{title: "Top Affected", lines: topAffectedLines(filtered, 5, 140), color: render.Green, weight: 2},
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; v cycles severity filter; g groups vulnerabilities; 1-6 switch tabs",
		emptyState:     "No policy findings found. Run with --audit to evaluate enriched vulnerability data.",
		items:          items,
	}
}

func (m *scanModel) vulnerabilityItems(findings []sdk.Finding) []listItem {
	group := strings.TrimSpace(m.vulnerabilityGroup)
	if group == "" {
		group = "component"
	}
	groups := make(map[string][]sdk.Finding)
	for _, finding := range findings {
		key := vulnerabilityGroupKey(finding, group)
		groups[key] = append(groups[key], finding)
	}
	keys := sortedFindingGroupKeys(groups)
	items := make([]listItem, 0, len(findings)+len(keys))
	for _, key := range keys {
		groupKey := group + ":" + key
		expanded, ok := m.vulnerabilityExpanded[groupKey]
		if !ok {
			expanded = true
		}
		groupFindings := groups[key]
		items = append(items, listItem{
			title:    fmt.Sprintf("%s (%d)", key, len(groupFindings)),
			subtitle: "group",
			details:  vulnerabilityGroupDetails(key, group, groupFindings),
			key:      groupKey,
			canOpen:  true,
			expanded: expanded,
		})
		if !expanded {
			continue
		}
		for idx, finding := range groupFindings {
			title := finding.ID
			if group != "component" {
				if pkgName := findingPackageName(finding); pkgName != "" {
					title += "  " + pkgName
				}
			}
			badges := []badge{}
			if group != "severity" {
				badges = append(badges, badge{label: finding.Severity, kind: "severity-" + strings.ToLower(finding.Severity)})
			}
			items = append(items, listItem{
				title:   title,
				badges:  badges,
				details: vulnerabilityDetails(finding),
				tree:    treePrefix(nil, idx == len(groupFindings)-1, 1),
				depth:   1,
			})
		}
	}
	return items
}

func sortedFindingGroupKeys(groups map[string][]sdk.Finding) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(groups[keys[i]]) != len(groups[keys[j]]) {
			return len(groups[keys[i]]) > len(groups[keys[j]])
		}
		return keys[i] < keys[j]
	})
	return keys
}

func vulnerabilityGroupKey(finding sdk.Finding, group string) string {
	switch group {
	case "severity":
		return titleCase(valueOrDefault(finding.Severity, "unknown"))
	case "ecosystem":
		if finding.Package != nil {
			return valueOrDefault(finding.Package.Ecosystem, "unknown")
		}
		return "unknown"
	default:
		return valueOrDefault(findingPackageName(finding), "unknown component")
	}
}

func findingPackageName(finding sdk.Finding) string {
	if finding.Package == nil {
		return ""
	}
	return packageDisplayName(finding.Package)
}

func (m *scanModel) vulnerabilityControlsLine() string {
	return keyHint("/", "search") + " " + keyHint("g", "group") + " " + keyHint("v", "severity") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all")
}

func (m *scanModel) vulnerabilityStateLine(showing, total int) string {
	return render.Style("Filter: ", render.Dim) + render.Style(valueOrDefault(m.severityFilter, "All"), render.BgYellow, render.Bold) +
		render.Style(" | Group: ", render.Dim) + render.Style(valueOrDefault(m.vulnerabilityGroup, "component"), render.BgYellow, render.Bold) +
		render.Style(" | Showing: ", render.Dim) + fmt.Sprintf("%d/%d", showing, total)
}

func vulnerabilitySummaryLines(findings []sdk.Finding) []string {
	counts := severityDistribution(findings)
	affected := make(map[string]struct{})
	for _, finding := range findings {
		if name := findingPackageName(finding); name != "" {
			affected[name] = struct{}{}
		}
	}
	return []string{
		severityColor("critical", fmt.Sprintf("%d Critical", counts["critical"])),
		severityColor("high", fmt.Sprintf("%d High", counts["high"])),
		severityColor("medium", fmt.Sprintf("%d Medium", counts["medium"])),
		severityColor("low", fmt.Sprintf("%d Low", counts["low"])),
		render.Style("Affected components: ", render.Dim) + fmt.Sprintf("%d", len(affected)),
	}
}

func topAffectedLines(findings []sdk.Finding, limit, width int) []string {
	counts := make(map[string]int)
	for _, finding := range findings {
		if name := findingPackageName(finding); name != "" {
			counts[name]++
		}
	}
	keys := sortedCountKeys(counts)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	if len(keys) == 0 {
		return []string{render.Style("(none)", render.Dim)}
	}
	max := maxCount(counts)
	lines := make([]string, 0, len(keys))
	for idx, key := range keys {
		labelWidth := width / 3
		if labelWidth < 18 {
			labelWidth = 18
		}
		if labelWidth > 34 {
			labelWidth = 34
		}
		barWidth := width - labelWidth - 3
		if barWidth < 10 {
			barWidth = 10
		}
		lines = append(lines, padRight(truncateToWidth(key, labelWidth), labelWidth)+render.Style(" ", render.Dim)+coloredBarLine(counts[key], max, barWidth, paletteColor(idx))+" "+fmt.Sprintf("%d", counts[key]))
	}
	return lines
}

func vulnerabilityGroupDetails(key, group string, findings []sdk.Finding) []string {
	lines := []string{
		render.Style("Group", render.Bold, render.Cyan),
		"",
		render.Style("  Name: ", render.Dim) + key,
		render.Style("  Grouping: ", render.Dim) + group,
		render.Style("  Vulnerabilities: ", render.Dim) + fmt.Sprintf("%d", len(findings)),
		"",
		render.Style(fmt.Sprintf("CVEs (%d)", len(findings)), render.Bold, render.Magenta),
	}
	for _, finding := range findings {
		lines = append(lines, render.Style("  - ", render.Dim)+finding.ID+" "+valueOrDash(finding.Title))
	}
	return lines
}

func vulnerabilityDetails(finding sdk.Finding) []string {
	lines := []string{
		render.Style("Vulnerability", render.Bold, render.Cyan),
		"",
		render.Style("  ID: ", render.Dim) + valueOrDash(finding.ID),
		render.Style("  Severity: ", render.Dim) + severityText(finding.Severity),
		render.Style("  Source: ", render.Dim) + valueOrDash(finding.Source),
		render.Style("  Package: ", render.Dim) + valueOrDash(findingPackageName(finding)),
		render.Style("  Title: ", render.Dim) + valueOrDash(finding.Title),
		render.Style("  KEV exploited: ", render.Dim) + fmt.Sprintf("%t", finding.KEVExploited),
		"",
		render.Style("Description", render.Bold, render.Magenta),
		"",
		render.Style("  ", render.Dim) + valueOrDash(finding.Description),
		"",
		render.Style("Versions", render.Bold, render.Magenta),
		"",
		render.Style("  Affected: ", render.Dim) + valueOrDash(finding.AffectedVersionRange),
		render.Style("  Fixed in: ", render.Dim) + valueOrDash(finding.FixedIn),
		"",
		render.Style(fmt.Sprintf("CVSS (%d)", len(finding.CVSS)), render.Bold, render.Magenta),
	}
	if len(finding.CVSS) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, score := range finding.CVSS {
			lines = append(lines, render.Style("  - ", render.Dim)+fmt.Sprintf("%.1f %s %s", score.Score, valueOrDash(score.Version), valueOrDash(score.Vector)))
		}
	}
	lines = append(lines, "", render.Style(fmt.Sprintf("References (%d)", len(finding.References)), render.Bold, render.Magenta))
	if len(finding.References) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, ref := range finding.References {
			lines = append(lines, render.Style("  - ", render.Dim)+valueOrDash(ref.URL)+" "+render.Style(valueOrDash(ref.Type), render.Dim))
		}
	}
	lines = append(lines, "", render.Style(fmt.Sprintf("Reasons (%d)", len(finding.Reasons)), render.Bold, render.Magenta))
	if len(finding.Reasons) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		lines = append(lines, indentLines(finding.Reasons)...)
	}
	return lines
}

func (m *scanModel) buildLicensesListModel() *listModel {
	rows := licenseRows(m.graphValue)
	totalComponents := graphSize(m.graphValue)
	items := m.licenseItems(rows, totalComponents)

	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewLicenses),
		controls:       []string{keyHint("/", "search") + " " + keyHint("g", "group") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all"), render.Style("Group: ", render.Dim) + render.Style(valueOrDefault(m.licenseGroup, "license"), render.BgYellow, render.Bold) + render.Style(" | Unique licenses: ", render.Dim) + fmt.Sprintf("%d", len(rows))},
		listTitle:      fmt.Sprintf("Licenses (%d)", len(rows)),
		listHeader:     padRight("License", 22) + padRight("Components", 11) + "Percentage",
		detailTitle:    "License Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; 1-6 switch tabs",
		emptyState:     "No license information found.",
		items:          items,
	}
}

func (m *scanModel) licenseItems(rows []licenseRow, totalComponents int) []listItem {
	group := valueOrDefault(m.licenseGroup, "license")
	if group == "license" {
		items := make([]listItem, 0, len(rows))
		for _, row := range rows {
			items = append(items, listItem{title: licenseTableRow(row, totalComponents, 48), details: licenseDetails(row)})
		}
		return items
	}
	grouped := make(map[string][]licenseRow)
	for _, row := range rows {
		key := licenseGroupKey(row, group)
		grouped[key] = append(grouped[key], row)
	}
	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(grouped[keys[i]]) != len(grouped[keys[j]]) {
			return len(grouped[keys[i]]) > len(grouped[keys[j]])
		}
		return keys[i] < keys[j]
	})
	items := make([]listItem, 0, len(rows)+len(keys))
	for _, key := range keys {
		groupKey := "license:" + group + ":" + key
		expanded := expandedValue(m.licenseExpanded, groupKey, true)
		groupRows := grouped[key]
		items = append(items, listItem{
			title:    fmt.Sprintf("%s (%d)", key, len(groupRows)),
			subtitle: "group",
			details:  licenseGroupDetails(key, group, groupRows),
			key:      groupKey,
			canOpen:  true,
			expanded: expanded,
		})
		if !expanded {
			continue
		}
		for idx, row := range groupRows {
			items = append(items, listItem{
				title:   licenseTableRow(row, totalComponents, 48),
				details: licenseDetails(row),
				tree:    treePrefix(nil, idx == len(groupRows)-1, 1),
				depth:   1,
			})
		}
	}
	return items
}

func licenseGroupKey(row licenseRow, group string) string {
	switch group {
	case "category":
		return licenseCategory(row.license)
	case "recognition":
		return render.StripANSI(licenseRecognition(row.license))
	default:
		return row.license
	}
}

func licenseGroupDetails(key, group string, rows []licenseRow) []string {
	components := 0
	for _, row := range rows {
		components += len(row.packages)
	}
	lines := []string{
		render.Style("License Group", render.Bold, render.Cyan),
		"",
		render.Style("  Name: ", render.Dim) + key,
		render.Style("  Grouping: ", render.Dim) + group,
		render.Style("  Licenses: ", render.Dim) + fmt.Sprintf("%d", len(rows)),
		render.Style("  Components: ", render.Dim) + fmt.Sprintf("%d", components),
	}
	return lines
}

func licenseTableRow(row licenseRow, totalComponents int, width int) string {
	percent := 0
	if totalComponents > 0 {
		percent = len(row.packages) * 100 / totalComponents
	}
	nameWidth := width - 28
	if nameWidth < 18 {
		nameWidth = 18
	}
	return padRight(truncateToWidth(row.license, nameWidth), nameWidth) +
		padRight(fmt.Sprintf("%d", len(row.packages)), 7) +
		coloredBarLine(len(row.packages), totalComponents, 12, render.Yellow) +
		fmt.Sprintf(" %d%%", percent)
}

func (m *scanModel) buildFindingsListModel() *listModel {
	items := m.findingItems(m.findings)
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewFindings),
		controls:       []string{keyHint("/", "search") + " " + keyHint("g", "group") + " " + keyHint("Enter", "inspect") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all"), render.Style("Group: ", render.Dim) + render.Style(valueOrDefault(m.findingGroup, "type"), render.BgYellow, render.Bold) + render.Style(" | Filter: ", render.Dim) + render.Style("All", render.BgYellow, render.Bold)},
		listTitle:      fmt.Sprintf("Findings (%d)", len(m.findings)),
		listHeader:     "Finding",
		detailTitle:    "Finding Details",
		topPanels:      []listPanel{{title: "Findings Summary", lines: findingSummaryLines(m.findings), color: render.Red, weight: 1}},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; 1-6 switch tabs",
		emptyState:     "No findings found. Run with --audit to evaluate available vulnerability data.",
		items:          items,
	}
}

func (m *scanModel) findingItems(findings []sdk.Finding) []listItem {
	group := valueOrDefault(m.findingGroup, "type")
	grouped := make(map[string][]sdk.Finding)
	for _, finding := range findings {
		grouped[findingGroupKey(finding, group)] = append(grouped[findingGroupKey(finding, group)], finding)
	}
	keys := sortedFindingGroupKeys(grouped)
	items := make([]listItem, 0, len(findings)+len(keys))
	for _, key := range keys {
		groupKey := "finding:" + group + ":" + key
		expanded := expandedValue(m.findingExpanded, groupKey, true)
		groupFindings := grouped[key]
		items = append(items, listItem{
			title:    fmt.Sprintf("%s (%d)", key, len(groupFindings)),
			subtitle: "group",
			details:  findingGroupDetails(key, group, groupFindings),
			key:      groupKey,
			canOpen:  true,
			expanded: expanded,
		})
		if !expanded {
			continue
		}
		for idx, finding := range groupFindings {
			items = append(items, listItem{
				title:    finding.ID,
				subtitle: string(finding.Kind),
				badges:   []badge{{label: finding.Severity, kind: "severity-" + strings.ToLower(finding.Severity)}},
				details:  findingDetails(finding),
				tree:     treePrefix(nil, idx == len(groupFindings)-1, 1),
				depth:    1,
			})
		}
	}
	return items
}

func findingGroupKey(finding sdk.Finding, group string) string {
	switch group {
	case "severity":
		return titleCase(valueOrDefault(finding.Severity, "unknown"))
	case "component":
		return valueOrDefault(findingPackageName(finding), "unknown component")
	case "ecosystem":
		if finding.Package != nil {
			return valueOrDefault(finding.Package.Ecosystem, "unknown")
		}
		return "unknown"
	default:
		return titleCase(string(finding.Kind))
	}
}

func findingGroupDetails(key, group string, findings []sdk.Finding) []string {
	return []string{
		render.Style("Finding Group", render.Bold, render.Cyan),
		"",
		render.Style("  Name: ", render.Dim) + key,
		render.Style("  Grouping: ", render.Dim) + group,
		render.Style("  Findings: ", render.Dim) + fmt.Sprintf("%d", len(findings)),
	}
}

func findingDetails(finding sdk.Finding) []string {
	pkg := ""
	if finding.Package != nil {
		pkg = packageDisplayName(finding.Package)
	}
	details := []string{
		render.Style("Finding", render.Bold, render.Cyan),
		"",
		render.Style("  ID: ", render.Dim) + valueOrDash(finding.ID),
		render.Style("  Kind: ", render.Dim) + valueOrDash(string(finding.Kind)),
		render.Style("  Severity: ", render.Dim) + severityText(finding.Severity),
		render.Style("  Package: ", render.Dim) + valueOrDash(pkg),
		render.Style("  Title: ", render.Dim) + valueOrDash(finding.Title),
		render.Style("  Source: ", render.Dim) + valueOrDash(finding.Source),
		render.Style("  Description: ", render.Dim) + valueOrDash(finding.Description),
		"",
		render.Style(fmt.Sprintf("Reasons (%d)", len(finding.Reasons)), render.Bold, render.Magenta),
		"",
	}
	return append(details, indentLines(finding.Reasons)...)
}

func findingSummaryLines(findings []sdk.Finding) []string {
	counts := make(map[string]int)
	for _, finding := range findings {
		counts[string(finding.Kind)]++
	}
	lines := []string{render.Style("Total: ", render.Dim) + fmt.Sprintf("%d", len(findings))}
	for _, key := range sortedCountKeys(counts) {
		lines = append(lines, fmt.Sprintf("%d %s", counts[key], titleCase(key)))
	}
	if len(lines) == 1 {
		lines = append(lines, render.Style("(none)", render.Dim))
	}
	return lines
}

func (m *scanModel) buildSourceListModel() *listModel {
	items := m.sourceExplorerItems()
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewSource),
		controls:       []string{keyHint("/", "search") + " " + keyHint("Enter", "toggle") + " " + keyHint("→", "expand") + " " + keyHint("←", "collapse") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all"), render.Style("Mode: ", render.Dim) + render.Style("JSON tree", render.BgYellow, render.Bold) + render.Style(" | Nodes: ", render.Dim) + fmt.Sprintf("%d", sourceNodeCount(m))},
		listTitle:      fmt.Sprintf("Source (%d nodes)", sourceNodeCount(m)),
		detailTitle:    "-",
		navigationHelp: interactiveCommonNavigationHelp + "; Enter expands/collapses source nodes",
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; 1-6 switch tabs",
		emptyState:     "No source data is available.",
		items:          items,
	}
}

func (m *scanModel) sourceExplorerItems() []listItem {
	items := []listItem{sourceNode("root: {}", "root", "", 0, true, expandedValue(m.sourceExpanded, "root", true))}
	if !expandedValue(m.sourceExpanded, "root", true) {
		return items
	}
	sections := []struct {
		key   string
		title string
		last  bool
	}{
		{"target", "target: {}", false},
		{"manifests", fmt.Sprintf("manifests: [] (%d items)", len(m.manifests)), false},
		{"packages", fmt.Sprintf("packages: [] (%d items)", graphSize(m.graphValue)), false},
		{"relationships", fmt.Sprintf("relationships: [] (%d items)", relationshipCount(m.graphValue)), true},
	}
	for _, section := range sections {
		tree := "├─ "
		if section.last {
			tree = "└─ "
		}
		expanded := expandedValue(m.sourceExpanded, section.key, section.key == "target")
		items = append(items, sourceNode(section.title, section.key, tree, 1, true, expanded))
		if !expanded {
			continue
		}
		prefix := "│  "
		if section.last {
			prefix = "   "
		}
		items = append(items, m.sourceSectionChildren(section.key, prefix)...)
	}
	return items
}

func (m *scanModel) sourceSectionChildren(section, prefix string) []listItem {
	switch section {
	case "target":
		lines := []string{
			fmt.Sprintf("name: %q", valueOrDash(m.project.Name)),
			fmt.Sprintf("path: %q", valueOrDash(m.project.Path)),
			fmt.Sprintf("type: %q", targetKindLabel(m.project)),
			fmt.Sprintf("ecosystem: %q", valueOrDash(m.project.Ecosystem)),
			fmt.Sprintf("packageManager: %q", valueOrDash(m.project.PackageManager)),
		}
		return sourceLeafItems(lines, prefix)
	case "manifests":
		out := make([]listItem, 0, len(m.manifests))
		for idx, manifest := range m.manifests {
			last := idx == len(m.manifests)-1
			tree := prefix + branch(last)
			out = append(out, sourceNode(fmt.Sprintf("%q: {ecosystem: %q, components: %d}", manifest.id, manifestEcosystem(m.graphValue, manifest), manifestComponentCount(m.graphValue, manifest.rootID)), "manifest:"+manifest.id, tree, 2, false, false))
		}
		return out
	case "packages":
		pkgs := []*sdk.Package{}
		if m.graphValue != nil {
			pkgs = append(pkgs, m.graphValue.Packages()...)
			sort.Slice(pkgs, func(i, j int) bool { return packageSortKey(pkgs[i]) < packageSortKey(pkgs[j]) })
		}
		out := make([]listItem, 0, len(pkgs)*8)
		for idx, pkg := range pkgs {
			last := idx == len(pkgs)-1
			tree := prefix + branch(last)
			key := "package:" + pkg.ID
			expanded := expandedValue(m.sourceExpanded, key, false)
			out = append(out, sourceNode(fmt.Sprintf("%q: {}", pkg.ID), key, tree, 2, true, expanded))
			if !expanded {
				continue
			}
			childPrefix := prefix
			if last {
				childPrefix += "   "
			} else {
				childPrefix += "│  "
			}
			out = append(out, sourceLeafItems(packageRawLines(pkg), childPrefix)...)
		}
		return out
	case "relationships":
		edges := relationshipRawLines(m.graphValue)
		return sourceLeafItems(edges, prefix)
	default:
		return nil
	}
}

func packageRawLines(pkg *sdk.Package) []string {
	if pkg == nil {
		return nil
	}
	licenseValues := pkg.LicenseValues()
	lines := []string{
		fmt.Sprintf("name: %q", valueOrDash(pkg.Name)),
		fmt.Sprintf("version: %q", valueOrDash(pkg.Version)),
		fmt.Sprintf("ecosystem: %q", valueOrDash(pkg.Ecosystem)),
		fmt.Sprintf("scope: %q", valueOrDash(pkg.Scope)),
		fmt.Sprintf("type: %q", valueOrDash(pkg.Type)),
		fmt.Sprintf("purl: %q", valueOrDash(pkg.PURL)),
		fmt.Sprintf("licenses: %q", strings.Join(licenseValues, ", ")),
		fmt.Sprintf("vulnerabilities: %d", len(pkg.Vulnerabilities)),
	}
	for idx, location := range pkg.Locations {
		lines = append(lines, fmt.Sprintf("locations[%d]: {realPath: %q, accessPath: %q}", idx, location.RealPath, location.AccessPath))
	}
	for idx, digest := range pkg.Digests {
		lines = append(lines, fmt.Sprintf("digests[%d]: {%s: %q}", idx, digest.Algorithm, digest.Value))
	}
	return lines
}

func relationshipRawLines(graphValue *sdk.Graph) []string {
	if graphValue == nil {
		return nil
	}
	pkgs := graphValue.Packages()
	sort.Slice(pkgs, func(i, j int) bool { return packageSortKey(pkgs[i]) < packageSortKey(pkgs[j]) })
	lines := make([]string, 0)
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		deps, err := graphValue.Dependencies(pkg.ID)
		if err != nil || len(deps) == 0 {
			continue
		}
		sort.Slice(deps, func(i, j int) bool { return packageSortKey(deps[i]) < packageSortKey(deps[j]) })
		for _, dep := range deps {
			if dep == nil {
				continue
			}
			lines = append(lines, fmt.Sprintf("%q -> %q", pkg.ID, dep.ID))
		}
	}
	return lines
}

func sourceLeafItems(lines []string, prefix string) []listItem {
	out := make([]listItem, 0, len(lines))
	for idx, line := range lines {
		out = append(out, sourceNode(line, "", prefix+branch(idx == len(lines)-1), 2, false, false))
	}
	return out
}

func sourceNode(title, key, tree string, depth int, canOpen, expanded bool) listItem {
	return listItem{title: title, key: key, tree: tree, depth: depth, canOpen: canOpen, expanded: expanded}
}

func branch(last bool) string {
	if last {
		return "└─ "
	}
	return "├─ "
}

func sourceNodeCount(m *scanModel) int {
	if m == nil {
		return 0
	}
	return 1 + 4 + 5 + len(m.manifests) + graphSize(m.graphValue) + relationshipCount(m.graphValue)
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
		"",
		render.Style("  Identifier: ", render.Dim) + valueOrDash(row.license),
		render.Style("  Full name: ", render.Dim) + licenseFullName(row.license),
		render.Style("  Text: ", render.Dim) + licenseTextURL(row.license),
		render.Style("  Category: ", render.Dim) + licenseCategory(row.license),
		render.Style("  Recognition: ", render.Dim) + licenseRecognition(row.license),
		render.Style("  Package count: ", render.Dim) + fmt.Sprintf("%d", len(row.packages)),
		"",
		render.Style(fmt.Sprintf("Components (%d)", len(row.packages)), render.Bold, render.Magenta),
		"",
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

func licenseFullName(value string) string {
	if isUnknownLicense(value) {
		return "Unknown"
	}
	return value
}

func licenseTextURL(value string) string {
	if isUnknownLicense(value) || !looksLikeSPDXLicense(value) {
		return "-"
	}
	return "https://spdx.org/licenses/" + value + ".html"
}

func licenseCategory(value string) string {
	lower := strings.ToLower(value)
	switch {
	case isUnknownLicense(value):
		return "Unknown"
	case strings.Contains(lower, "gpl") || strings.Contains(lower, "lgpl") || strings.Contains(lower, "agpl"):
		return "Copyleft"
	case strings.Contains(lower, "mit") || strings.Contains(lower, "apache") || strings.Contains(lower, "bsd") || strings.Contains(lower, "isc"):
		return "Permissive"
	default:
		return "Unclassified"
	}
}

func licenseRecognition(value string) string {
	switch {
	case isUnknownLicense(value):
		return render.Style("unknown", render.Yellow, render.Bold)
	case looksLikeSPDXLicense(value):
		return render.Style("recognized", render.Green, render.Bold)
	default:
		return render.Style("unrecognized expression", render.Yellow, render.Bold)
	}
}

func (m *scanModel) buildComponentListModel(manifest listPackageRow) *listModel {
	if m.explainMode {
		return m.buildExplainComponentListModel(manifest)
	}
	rootPkg, _ := m.graphValue.Package(manifest.rootID)

	rows := m.componentTreeRows(manifest.rootID)
	// Compute highest severity per package for badge display, filtering, and sorting.
	maxSevByID := maxSeverityByPkgID(m.findings)
	rows = m.filterComponentRows(rows, maxSevByID)

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
		deps, _ := m.graphValue.Dependencies(row.id)
		expanded := m.componentExpanded[row.id]
		if row.relationship == "root" {
			expanded = true
			if _, ok := m.componentExpanded[row.id]; ok {
				expanded = m.componentExpanded[row.id]
			}
		}
		if row.repeated {
			deps = nil
			expanded = false
		}
		items = append(items, listItem{
			title:    row.displayName,
			subtitle: row.relationship,
			badges:   badges,
			details:  componentDetails(m.graphValue, row, manifest, m.findings),
			key:      row.id,
			tree:     row.tree,
			depth:    row.depth,
			canOpen:  len(deps) > 0,
			expanded: expanded,
		})
	}

	navigationHelp := interactiveCommonNavigationHelp
	if m.allowManifestExit {
		navigationHelp += "; Backspace/Left/h returns to manifests"
	}

	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewPackages),
		controls:       []string{m.componentControlsLine() + render.Style(" | Manifest: ", render.Dim) + manifest.displayName + render.Style(" | Root: ", render.Dim) + packageDisplayName(rootPkg)},
		listTitle:      fmt.Sprintf("Components (%d)", len(rows)),
		detailTitle:    "Component Details",
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
	maxSevByID := maxSeverityByPkgID(m.findings)
	rows = m.filterComponentRows(rows, maxSevByID)
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
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewPackages),
		controls:       []string{m.componentControlsLine() + render.Style(" | Target: ", render.Dim) + packageDisplayName(targetPkg) + render.Style(" | Self/Parents/Ancestors/Roots: ", render.Dim) + fmt.Sprintf("%d/%d/%d/%d", counts["self"], counts["parent"], counts["ancestor"], counts["root"])},
		listTitle:      fmt.Sprintf("Components (%d)", len(rows)),
		detailTitle:    "Component Details",
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
			id:               manifestID,
			rootID:           rootID,
			targetID:         manifestTargetID(manifest.Entry.Graph),
			displayName:      manifestName,
			ecosystem:        string(manifest.Subproject.Ecosystem),
			relationship:     "manifest",
			detectorName:     valueOrDefault(manifest.DetectorName, manifest.Subproject.PrimaryDetector),
			origin:           string(manifest.Origin),
			technique:        string(manifest.Technique),
			packageManagers:  packageManagersLabel(manifest.Subproject.DetectedPackageManagers),
			plannedDetectors: strings.Join(manifest.Subproject.PlannedDetectors, ", "),
			relativePath:     manifest.Subproject.RelativePath,
			targetKind:       string(manifest.Subproject.ExecutionTarget.Kind),
			targetLocation:   manifest.Subproject.ExecutionTarget.Location,
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
		render.Style("  Ecosystem: ", render.Dim) + valueOrDash(row.ecosystem),
		render.Style("  Package managers: ", render.Dim) + valueOrDash(row.packageManagers),
		render.Style("  Relative path: ", render.Dim) + valueOrDash(row.relativePath),
		render.Style("  Target: ", render.Dim) + valueOrDash(row.targetLocation),
		"",
		render.Style("Detector", render.Bold, render.Magenta),
		render.Style("  Name: ", render.Dim) + valueOrDash(row.detectorName),
		render.Style("  Origin: ", render.Dim) + valueOrDash(row.origin),
		render.Style("  Technique: ", render.Dim) + valueOrDash(row.technique),
		render.Style("  Planned chain: ", render.Dim) + valueOrDash(row.plannedDetectors),
		render.Style("  Target type: ", render.Dim) + valueOrDash(row.targetKind),
		"",
		render.Style("Dependencies", render.Bold, render.Cyan),
		render.Style("  Root (project package): ", render.Dim) + packageDisplayName(rootPkg),
		render.Style("  Direct dependencies: ", render.Dim) + fmt.Sprintf("%d", len(groups.direct)),
		render.Style("  Transitive dependencies: ", render.Dim) + fmt.Sprintf("%d", len(groups.transitive)),
		"",
		render.Style("Press Enter to view components for this manifest.", render.Dim),
		"",
	}
	return lines
}

func packageManagersLabel(managers []sdk.PackageManager) string {
	if len(managers) == 0 {
		return ""
	}
	labels := make([]string, 0, len(managers))
	for _, manager := range managers {
		labels = append(labels, manager.Name())
	}
	return strings.Join(labels, ", ")
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
		ecosystem:    pkg.Ecosystem,
		relationship: relationship,
		purl:         pkg.PURL,
	}
}

func (m *scanModel) componentTreeRows(rootID string) []listPackageRow {
	if m == nil || m.graphValue == nil || strings.TrimSpace(rootID) == "" {
		return nil
	}
	rootPkg, ok := m.graphValue.Package(rootID)
	if !ok || rootPkg == nil {
		return nil
	}
	rows := make([]listPackageRow, 0)
	renderedSubtrees := make(map[string]struct{})
	var walk func(pkg *sdk.Package, depth int, ancestors []bool, last bool, visited map[string]struct{})
	walk = func(pkg *sdk.Package, depth int, ancestors []bool, last bool, visited map[string]struct{}) {
		if pkg == nil {
			return
		}
		relationship := "transitive"
		switch depth {
		case 0:
			relationship = "root"
		case 1:
			relationship = "direct"
		}
		row := packageRowFromGraph(pkg, relationship)
		row.depth = depth
		row.tree = treePrefix(ancestors, last, depth)
		if depth > 0 {
			if _, repeated := renderedSubtrees[pkg.ID]; repeated {
				row.repeated = true
				rows = append(rows, row)
				return
			}
		}
		rows = append(rows, row)

		expanded := m.componentExpanded[pkg.ID]
		if depth == 0 {
			expanded = true
			if _, ok := m.componentExpanded[pkg.ID]; ok {
				expanded = m.componentExpanded[pkg.ID]
			}
		}
		if !expanded {
			return
		}
		deps, err := m.graphValue.Dependencies(pkg.ID)
		if err != nil || len(deps) == 0 {
			return
		}
		renderedSubtrees[pkg.ID] = struct{}{}
		sort.Slice(deps, func(i, j int) bool {
			return packageSortKey(deps[i]) < packageSortKey(deps[j])
		})
		nextVisited := make(map[string]struct{}, len(visited)+1)
		for key := range visited {
			nextVisited[key] = struct{}{}
		}
		nextVisited[pkg.ID] = struct{}{}
		children := make([]*sdk.Package, 0, len(deps))
		for _, dep := range deps {
			if dep == nil {
				continue
			}
			if _, seen := nextVisited[dep.ID]; seen {
				continue
			}
			children = append(children, dep)
		}
		childAncestors := ancestors
		if depth > 0 {
			childAncestors = append(append([]bool(nil), ancestors...), last)
		}
		for idx, dep := range children {
			walk(dep, depth+1, childAncestors, idx == len(children)-1, nextVisited)
		}
	}
	walk(rootPkg, 0, nil, true, map[string]struct{}{})
	return rows
}

func treePrefix(ancestors []bool, last bool, depth int) string {
	if depth <= 0 {
		return ""
	}
	var b strings.Builder
	for _, ancestorLast := range ancestors {
		if ancestorLast {
			b.WriteString("   ")
		} else {
			b.WriteString("│  ")
		}
	}
	if last {
		b.WriteString("└─ ")
	} else {
		b.WriteString("├─ ")
	}
	return b.String()
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
		"",
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
		lines = append(lines, render.Style(fmt.Sprintf("%s (%d)", title, len(packages)), render.Bold, render.Magenta), "")
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
	if row.repeated {
		lines = append(lines,
			render.Style("Repeated branch", render.Bold, render.Yellow),
			"",
			render.Style("  This component already appears earlier in the tree; its dependency branch is not repeated here.", render.Dim),
			"",
		)
	}

	// Vulnerabilities section
	var pkgFindings []sdk.Finding
	for _, f := range findings {
		if f.Kind == sdk.FindingKindVulnerability && f.Package != nil && f.Package.ID == row.id {
			pkgFindings = append(pkgFindings, f)
		}
	}
	lines = append(lines, render.Style(fmt.Sprintf("Vulnerabilities (%d)", len(pkgFindings)), render.Bold, render.Cyan), "")
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
	var pkg *sdk.Package
	if graphValue != nil {
		pkg, _ = graphValue.Package(row.id)
	}
	licenseCount := 0
	if pkg != nil {
		licenseCount = len(pkg.Licenses)
	}
	lines = append(lines, render.Style(fmt.Sprintf("Licenses (%d)", licenseCount), render.Bold, render.Cyan), "")
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

func compactDistributionLines(counts map[string]int, limit int) []string {
	keys := sortedCountKeys(counts)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	if len(keys) == 0 {
		return []string{render.Style("(none)", render.Dim)}
	}
	max := maxCount(counts)
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, padRight(key, 18)+barLine(counts[key], max))
	}
	return lines
}

func compactLicenseLines(graphValue *sdk.Graph, limit int) []string {
	counts := make(map[string]int)
	for _, row := range licenseRows(graphValue) {
		counts[row.license] = len(row.packages)
	}
	return compactDistributionLines(counts, limit)
}

func severityTinySummary(counts map[string]int) string {
	parts := make([]string, 0, 4)
	for _, key := range []string{"critical", "high", "medium", "low"} {
		parts = append(parts, fmt.Sprintf("%s %d", strings.ToUpper(key[:1]), counts[key]))
	}
	return strings.Join(parts, " ")
}

func summaryCountCardLines(count int, unit string, width int, color string, extra ...string) []string {
	lines := []string{
		centerLine(render.Style(fmt.Sprintf("%d", count), color, render.Bold), width),
		centerLine(render.Style(unit, render.Dim), width),
	}
	return append(lines, extra...)
}

func severityCardLine(findings []sdk.Finding, severity string) string {
	counts := severityDistribution(findings)
	label := titleCase(severity)
	return severityColor(severity, fmt.Sprintf("%d %s", counts[severity], label))
}

func severityDistributionLines(findings []sdk.Finding, width int) []string {
	counts := severityDistribution(findings)
	total := 0
	for _, severity := range []string{"critical", "high", "medium", "low", "unknown"} {
		total += counts[severity]
	}
	max := maxCount(counts)
	lines := make([]string, 0, 5)
	for _, severity := range []string{"critical", "high", "medium", "low", "unknown"} {
		label := titleCase(severity)
		lines = append(lines, distributionLine(label, counts[severity], total, max, severityColorCode(severity), width))
	}
	return lines
}

func coloredDistributionLines(counts map[string]int, total, limit, width int) []string {
	keys := sortedCountKeys(counts)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	if len(keys) == 0 {
		return []string{render.Style("(none)", render.Dim)}
	}
	max := maxCount(counts)
	lines := make([]string, 0, len(keys))
	for idx, key := range keys {
		lines = append(lines, distributionLine(key, counts[key], total, max, paletteColor(idx), width))
	}
	return lines
}

func distributionLine(label string, value, total, max int, color string, width int) string {
	if width < 32 {
		width = 32
	}
	percent := 0
	if total > 0 {
		percent = value * 100 / total
	}
	text := fmt.Sprintf("%d %s (%d%%)", value, label, percent)
	barWidth := width - 26
	if barWidth < 8 {
		barWidth = 8
	}
	return padRight(truncateToWidth(text, 22), 24) + coloredBarLine(value, max, barWidth, color)
}

func coloredBarLine(value, max, width int, color string) string {
	filled := 0
	if max > 0 {
		filled = value * width / max
		if value > 0 && filled == 0 {
			filled = 1
		}
	}
	if color == "" {
		color = render.Green
	}
	return render.Style(strings.Repeat("█", filled), color) + render.Style(strings.Repeat("░", width-filled), render.Dim)
}

func severityColor(severity, value string) string {
	return render.Style(value, severityColorCode(severity), render.Bold)
}

func severityColorCode(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return render.Purple
	case "high":
		return render.Red
	case "medium":
		return render.Orange
	case "low":
		return render.Green
	default:
		return render.Gray
	}
}

func titleCase(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.ToUpper(value[:1]) + strings.ToLower(value[1:])
}

func paletteColor(idx int) string {
	palette := []string{render.Green, render.Cyan, render.Yellow, render.Red, render.Blue, render.Magenta}
	return palette[idx%len(palette)]
}

func unknownLicenseCount(graphValue *sdk.Graph) int {
	count := 0
	for _, row := range licenseRows(graphValue) {
		if isUnknownLicense(row.license) {
			count += len(row.packages)
		}
	}
	return count
}

func unrecognizedLicenseCount(graphValue *sdk.Graph) int {
	count := 0
	for _, row := range licenseRows(graphValue) {
		if !isUnknownLicense(row.license) && !looksLikeSPDXLicense(row.license) {
			count += len(row.packages)
		}
	}
	return count
}

func isUnknownLicense(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "" || value == "unknown" || value == "noassertion" || value == "none"
}

func looksLikeSPDXLicense(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.Contains(value, " ") || strings.Contains(value, "(") || strings.Contains(value, ")") {
		return false
	}
	return strings.Contains(value, "-") || strings.EqualFold(value, "MIT") || strings.EqualFold(value, "ISC") || strings.EqualFold(value, "BSD")
}

func groupedLicenseCounts(graphValue *sdk.Graph, limit int) map[string]int {
	counts := make(map[string]int)
	for _, row := range licenseRows(graphValue) {
		counts[row.license] = len(row.packages)
	}
	keys := sortedCountKeys(counts)
	if len(keys) <= limit {
		return counts
	}
	grouped := make(map[string]int, limit)
	keep := limit - 1
	if keep < 1 {
		keep = 1
	}
	for idx, key := range keys {
		if idx < keep {
			grouped[key] = counts[key]
		} else {
			grouped["Other"] += counts[key]
		}
	}
	return grouped
}

type componentStat struct {
	name          string
	vulns         int
	maxSeverity   string
	dependents    int
	displayVulns  int
	displayPctMax int
}

func topVulnerableComponentStats(graphValue *sdk.Graph, findings []sdk.Finding, limit int) []componentStat {
	counts, severities := packageVulnerabilityStats(graphValue, findings)
	stats := make([]componentStat, 0, len(counts))
	for name, count := range counts {
		stats = append(stats, componentStat{name: name, vulns: count, maxSeverity: severities[name]})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].vulns != stats[j].vulns {
			return stats[i].vulns > stats[j].vulns
		}
		if severityRank(stats[i].maxSeverity) != severityRank(stats[j].maxSeverity) {
			return severityRank(stats[i].maxSeverity) < severityRank(stats[j].maxSeverity)
		}
		return stats[i].name < stats[j].name
	})
	if len(stats) > limit {
		stats = stats[:limit]
	}
	return stats
}

func topDependedOnComponentStats(graphValue *sdk.Graph, findings []sdk.Finding, limit int) []componentStat {
	vulnCounts, _ := packageVulnerabilityStats(graphValue, findings)
	stats := make([]componentStat, 0)
	if graphValue != nil {
		for _, pkg := range graphValue.Packages() {
			if pkg == nil {
				continue
			}
			dependents := transitiveDependentCount(graphValue, pkg.ID)
			if dependents == 0 {
				continue
			}
			name := packageDisplayName(pkg)
			stats = append(stats, componentStat{name: name, dependents: dependents, vulns: vulnCounts[name]})
		}
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].dependents != stats[j].dependents {
			return stats[i].dependents > stats[j].dependents
		}
		return stats[i].name < stats[j].name
	})
	if len(stats) > limit {
		stats = stats[:limit]
	}
	return stats
}

func packageVulnerabilityStats(graphValue *sdk.Graph, findings []sdk.Finding) (map[string]int, map[string]string) {
	counts := make(map[string]int)
	severities := make(map[string]string)
	if graphValue != nil {
		for _, pkg := range graphValue.Packages() {
			if pkg == nil || len(pkg.Vulnerabilities) == 0 {
				continue
			}
			name := packageDisplayName(pkg)
			counts[name] += len(pkg.Vulnerabilities)
			for _, vuln := range pkg.Vulnerabilities {
				if severityRank(vuln.Severity) < severityRank(severities[name]) {
					severities[name] = vuln.Severity
				}
			}
		}
	}
	for _, finding := range findings {
		if finding.Package == nil {
			continue
		}
		name := packageDisplayName(finding.Package)
		counts[name]++
		if severityRank(finding.Severity) < severityRank(severities[name]) {
			severities[name] = finding.Severity
		}
	}
	return counts, severities
}

func topVulnerableTableLines(stats []componentStat, width int) []string {
	if len(stats) == 0 {
		return []string{render.Style("(none)", render.Dim)}
	}
	lines := []string{render.Style(padRight("Component", width-22)+padRight("Vulns", 8)+"Max Severity", render.Dim)}
	for _, stat := range stats {
		line := padRight(truncateToWidth(stat.name, width-22), width-22) +
			padRight(fmt.Sprintf("%d", stat.vulns), 8) +
			severityText(valueOrDash(stat.maxSeverity))
		lines = append(lines, line)
	}
	return lines
}

func topDependedOnTableLines(stats []componentStat, width int) []string {
	if len(stats) == 0 {
		return []string{render.Style("(none)", render.Dim)}
	}
	lines := []string{render.Style(padRight("Component", width-28)+padRight("Dependents", 14)+"Vulns", render.Dim)}
	for _, stat := range stats {
		line := padRight(truncateToWidth(stat.name, width-28), width-28) +
			padRight(fmt.Sprintf("%d", stat.dependents), 14) +
			fmt.Sprintf("%d", stat.vulns)
		lines = append(lines, line)
	}
	return lines
}

func componentsByRelationshipLines(manifests []listPackageRow, graphValue *sdk.Graph, width int) []string {
	if len(manifests) == 0 {
		return []string{render.Style("(none)", render.Dim)}
	}
	nameWidth := width - 36
	if nameWidth < 16 {
		nameWidth = 16
	}
	lines := []string{render.Style(padRight("Manifest", nameWidth)+padRight("Direct", 8)+padRight("Transitive", 12)+"Root", render.Dim)}
	displayed, remaining := displayManifestsWithRemainder(manifests, 10)
	for _, manifest := range displayed {
		counts := map[string]int{"root": 0, "direct": 0, "transitive": 0}
		for _, row := range componentCountRows(graphValue, manifest.rootID) {
			counts[valueOrDefault(row.relationship, "transitive")]++
		}
		lines = append(lines,
			padRight(truncateToWidth(manifest.displayName, nameWidth), nameWidth)+
				padRight(fmt.Sprintf("%d", counts["direct"]), 8)+
				padRight(fmt.Sprintf("%d", counts["transitive"]), 12)+
				fmt.Sprintf("%d", counts["root"]),
		)
	}
	if remaining > 0 {
		lines = append(lines, render.Style(fmt.Sprintf("+ %d more manifests", remaining), render.Dim))
	}
	return lines
}

func componentsByScopeLines(manifests []listPackageRow, graphValue *sdk.Graph, width int) []string {
	if len(manifests) == 0 {
		return []string{render.Style("(none)", render.Dim)}
	}
	nameWidth := width - 42
	if nameWidth < 16 {
		nameWidth = 16
	}
	lines := []string{render.Style(padRight("Manifest", nameWidth)+padRight("Runtime", 9)+padRight("Development", 13)+"Unset", render.Dim)}
	displayed, remaining := displayManifestsWithRemainder(manifests, 10)
	for _, manifest := range displayed {
		counts := map[string]int{"runtime": 0, "development": 0, "unset": 0}
		for _, row := range componentCountRows(graphValue, manifest.rootID) {
			scope := valueOrDefault(row.scope, "unset")
			if _, ok := counts[scope]; !ok {
				scope = "unset"
			}
			counts[scope]++
		}
		lines = append(lines,
			padRight(truncateToWidth(manifest.displayName, nameWidth), nameWidth)+
				padRight(fmt.Sprintf("%d", counts["runtime"]), 9)+
				padRight(fmt.Sprintf("%d", counts["development"]), 13)+
				fmt.Sprintf("%d", counts["unset"]),
		)
	}
	if remaining > 0 {
		lines = append(lines, render.Style(fmt.Sprintf("+ %d more manifests", remaining), render.Dim))
	}
	return lines
}

func displayManifestsWithRemainder(manifests []listPackageRow, limit int) ([]listPackageRow, int) {
	if limit <= 0 || len(manifests) <= limit {
		return manifests, 0
	}
	return manifests[:limit], len(manifests) - limit
}

func vulnerableComponentTotal(graphValue *sdk.Graph, findings []sdk.Finding) int {
	counts, _ := packageVulnerabilityStats(graphValue, findings)
	return len(counts)
}

func dependedOnComponentTotal(graphValue *sdk.Graph) int {
	count := 0
	if graphValue == nil {
		return count
	}
	for _, pkg := range graphValue.Packages() {
		if pkg == nil {
			continue
		}
		if transitiveDependentCount(graphValue, pkg.ID) > 0 {
			count++
		}
	}
	return count
}

func transitiveDependentCount(graphValue *sdk.Graph, packageID string) int {
	if graphValue == nil || strings.TrimSpace(packageID) == "" {
		return 0
	}
	seen := make(map[string]struct{})
	queue := []string{packageID}
	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]
		dependents, err := graphValue.Dependents(currentID)
		if err != nil {
			continue
		}
		for _, dependent := range dependents {
			if dependent == nil || dependent.ID == packageID {
				continue
			}
			if _, ok := seen[dependent.ID]; ok {
				continue
			}
			seen[dependent.ID] = struct{}{}
			queue = append(queue, dependent.ID)
		}
	}
	return len(seen)
}

func stackBoxes(boxes ...[]string) []string {
	out := make([]string, 0)
	for idx, box := range boxes {
		if idx > 0 {
			out = append(out, "")
		}
		out = append(out, box...)
	}
	return out
}

func licenseDistributionDetails(graphValue *sdk.Graph) []string {
	counts := make(map[string]int)
	for _, row := range licenseRows(graphValue) {
		counts[row.license] = len(row.packages)
	}
	return distributionDetails("License Distribution", counts)
}

func topVulnerableComponentDetails(findings []sdk.Finding) []string {
	return distributionDetails("Top Vulnerable Components", topCounts(topVulnerableCounts(findings), 10))
}

func topDependedOnDetails(graphValue *sdk.Graph) []string {
	return distributionDetails("Top Depended-On Components", topCounts(topDependedOnCounts(graphValue), 10))
}

func topVulnerableCounts(findings []sdk.Finding) map[string]int {
	counts := make(map[string]int)
	for _, finding := range findings {
		if finding.Package == nil {
			continue
		}
		counts[packageDisplayName(finding.Package)]++
	}
	return counts
}

func topDependedOnCounts(graphValue *sdk.Graph) map[string]int {
	counts := make(map[string]int)
	if graphValue == nil {
		return counts
	}
	for _, pkg := range graphValue.Packages() {
		if pkg == nil {
			continue
		}
		dependents, err := graphValue.Dependents(pkg.ID)
		if err == nil && len(dependents) > 0 {
			counts[packageDisplayName(pkg)] = len(dependents)
		}
	}
	return counts
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
	return render.Style(strings.Repeat("█", filled), render.Green) + render.Style(strings.Repeat("░", width-filled), render.Dim) + fmt.Sprintf(" %d", value)
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
		"",
		render.Style("  Target: ", render.Dim) + valueOrDash(m.project.Name),
		render.Style("  Type: ", render.Dim) + targetKindLabel(m.project),
		render.Style("  Packages: ", render.Dim) + fmt.Sprintf("%d", graphSize(m.graphValue)),
		render.Style("  Relationships: ", render.Dim) + fmt.Sprintf("%d", relationshipCount(m.graphValue)),
		render.Style("  Manifests: ", render.Dim) + fmt.Sprintf("%d", len(m.manifests)),
		render.Style("  Nodes: ", render.Dim) + fmt.Sprintf("%d", sourceNodeCount(m)),
		"",
		render.Style("Press Enter to expand or collapse source nodes.", render.Dim),
	}
}

func sourceTargetDetails(m *scanModel) []string {
	return []string{
		render.Style("Target", render.Bold, render.Cyan),
		"",
		render.Style("  Name: ", render.Dim) + valueOrDash(m.project.Name),
		render.Style("  Path: ", render.Dim) + valueOrDash(m.project.Path),
		render.Style("  Type: ", render.Dim) + targetKindLabel(m.project),
		render.Style("  Ecosystem: ", render.Dim) + valueOrDash(m.project.Ecosystem),
		render.Style("  Package manager: ", render.Dim) + valueOrDash(m.project.PackageManager),
	}
}

func sourceManifestDetails(m *scanModel) []string {
	lines := []string{render.Style(fmt.Sprintf("Manifests (%d)", len(m.manifests)), render.Bold, render.Cyan), ""}
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
	case strings.TrimSpace(project.TargetType) != "":
		return project.TargetType
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
