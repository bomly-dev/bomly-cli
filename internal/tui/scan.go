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
		sourceExpanded:        map[string]bool{"root": true},
		componentExpanded:     map[string]bool{},
		vulnerabilityGroup:    "component",
		vulnerabilityExpanded: map[string]bool{},
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
		m.list = m.buildCurrentListModel()
		return
	}
	if m.activeView == interactiveScanViewVulns && item.canOpen && item.key != "" {
		m.vulnerabilityExpanded[item.key] = !item.expanded
		m.list = m.buildCurrentListModel()
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
	m.list = m.buildCurrentListModel()
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
	case interactiveScanViewSource:
		m.sourceExpanded[item.key] = expanded
	default:
		return
	}
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) CycleGroup() {
	if m == nil || m.activeView != interactiveScanViewVulns {
		return
	}
	values := []string{"component", "severity", "ecosystem"}
	for idx, value := range values {
		if m.vulnerabilityGroup == value {
			m.vulnerabilityGroup = values[(idx+1)%len(values)]
			m.list = m.buildCurrentListModel()
			return
		}
	}
	m.vulnerabilityGroup = values[0]
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) CycleRelationshipFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages {
		return
	}
	m.relationshipFilter = nextRelationshipFilter(m.relationshipFilter, m.explainMode)
	m.list = m.buildCurrentListModel()
}

func (m *scanModel) CycleScopeFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages {
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
	default:
		return
	}
	m.severityFilter = nextSeverityFilter(m.severityFilter)
	m.list = m.buildCurrentListModel()
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
		"",
		m.tabLine(active),
		"",
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
	return keyHint("/", "search") + " " + keyHint("r", "relationship") + " " + keyHint("s", "scope") + " " + keyHint("v", "severity")
}

func (m *scanModel) componentStateLine(extra string) string {
	state := render.Style("Group: ", render.Dim) + render.Style("Dependency", render.BgYellow, render.Bold) +
		render.Style(" | Relationship: ", render.Dim) + render.Style(valueOrDefault(m.relationshipFilter, "All"), render.BgYellow, render.Bold) +
		render.Style(" | Scope: ", render.Dim) + render.Style(valueOrDefault(m.scopeFilter, "All"), render.BgYellow, render.Bold) +
		render.Style(" | Severity: ", render.Dim) + render.Style(valueOrDefault(m.severityFilter, "All"), render.BgYellow, render.Bold)
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
		details:  projectDetails(m, packageCount(m.graphValue)),
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
	items := make([]listItem, 0, totalComponents+len(m.manifests)+1)
	projectKey := "project"
	projectExpanded := expandedValue(m.componentExpanded, projectKey, true)
	items = append(items, listItem{
		title:    fmt.Sprintf("%s (%d manifests)", valueOrDash(m.project.Name), len(m.manifests)),
		subtitle: "project",
		details:  projectDetails(m, totalComponents),
		key:      projectKey,
		canOpen:  len(m.manifests) > 0,
		expanded: projectExpanded,
	})
	maxSevByID := maxSeverityByPkgID(m.findings)
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
				title:    fmt.Sprintf("%s (%s, %d components)", manifest.displayName, manifestEcosystem(m.graphValue, manifest), manifestComponentCount(m.graphValue, manifest.rootID)),
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
			rows = filterPackageRows(rows, m.relationshipFilter, m.scopeFilter)
			if m.severityFilter != "" {
				kept := rows[:0]
				for _, row := range rows {
					if strings.EqualFold(maxSevByID[row.id], m.severityFilter) {
						kept = append(kept, row)
					}
				}
				rows = kept
			}
			for _, row := range rows {
				badges := packageBadges(row)
				if sev := maxSevByID[row.id]; sev != "" {
					badges = append([]badge{{label: sev, kind: "severity-" + strings.ToLower(sev)}}, badges...)
				}
				deps, _ := m.graphValue.Dependencies(row.id)
				expanded := expandedValue(m.componentExpanded, row.id, row.relationship == "root")
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
		controls:       []string{m.componentControlsLine(), m.componentStateLine(fmt.Sprintf("Components: %d", totalComponents))},
		listTitle:      fmt.Sprintf("Components (%d)", totalComponents),
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

func projectDetails(m *scanModel, components int) []string {
	return []string{
		render.Style("Project", render.Bold, render.Cyan),
		"",
		render.Style("  Name: ", render.Dim) + valueOrDash(m.project.Name),
		render.Style("  Path: ", render.Dim) + valueOrDash(m.project.Path),
		render.Style("  Type: ", render.Dim) + targetKindLabel(m.project),
		render.Style("  Manifests: ", render.Dim) + fmt.Sprintf("%d", len(m.manifests)),
		render.Style("  Components: ", render.Dim) + fmt.Sprintf("%d", components),
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
		boxView("Components", []string{
			centerLine(render.Style(fmt.Sprintf("%d", stats.components), render.Cyan, render.Bold), summaryWidth-2),
			fmt.Sprintf("%d ecosystems", len(stats.ecosystems)),
			fmt.Sprintf("%d manifests", len(m.manifests)),
		}, summaryWidth, cardHeight, render.Cyan),
		boxView("Vulnerabilities", []string{
			centerLine(severityText(fmt.Sprintf("%d", stats.vulnerabilities)), summaryWidth-2),
			severityCardLine(m.findings, "critical"),
			severityCardLine(m.findings, "high"),
			severityCardLine(m.findings, "medium"),
			severityCardLine(m.findings, "low"),
		}, summaryWidth, cardHeight, render.Red),
		boxView("Licenses", []string{
			centerLine(render.Style(fmt.Sprintf("%d", stats.licenses), render.Yellow, render.Bold), summaryWidth-2),
			"unique licenses",
			fmt.Sprintf("%d unknown", unknownLicenseCount(m.graphValue)),
			fmt.Sprintf("%d unrecognized", unrecognizedLicenseCount(m.graphValue)),
		}, summaryWidth, cardHeight, render.Yellow),
		boxView("Target", []string{
			render.Style("Name: ", render.Dim) + valueOrDash(m.project.Name),
			render.Style("Type: ", render.Dim) + targetKindLabel(m.project),
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
	topDeps := topDependedOnComponentStats(m.graphValue, m.findings, 8)
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
		boxView("Vulnerability Severity", severityDistributionLines(m.findings, leftWidth-2), leftWidth, leftA, render.Red),
		boxView("Ecosystem Distribution", coloredDistributionLines(stats.ecosystems, stats.components, 8, leftWidth-2), leftWidth, leftB, render.Cyan),
		boxView("License Distribution", coloredDistributionLines(groupedLicenseCounts(m.graphValue, 10), stats.components, 10, leftWidth-2), leftWidth, leftC, render.Yellow),
	)
	rightA := remaining / 2
	rightB := remaining - rightA - 1
	if rightB < 4 {
		rightB = 4
	}
	rightContent := stackBoxes(
		boxView(fmt.Sprintf("Top Vulnerable Components (%d)", vulnerableComponentTotal(m.graphValue, m.findings)), topVulnerableTableLines(topVuln, rightWidth-2), rightWidth, rightA, render.Red),
		boxView(fmt.Sprintf("Top Depended-On Components (%d)", dependedOnComponentTotal(m.graphValue)), topDependedOnTableLines(topDeps, rightWidth-2), rightWidth, rightB, render.Green),
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
			{title: "Top Affected", lines: topAffectedLines(filtered, 5, 90), color: render.Green, weight: 2},
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
	return keyHint("/", "search") + " " + keyHint("g", "group") + " " + keyHint("v", "severity")
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
	for _, key := range keys {
		labelWidth := 26
		if width < 48 {
			labelWidth = 18
		}
		barWidth := width - labelWidth - 6
		if barWidth < 10 {
			barWidth = 10
		}
		lines = append(lines, padRight(truncateToWidth(key, labelWidth), labelWidth)+padRight(fmt.Sprintf("%d", counts[key]), 6)+coloredBarLine(counts[key], max, barWidth, render.Green))
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
	items := make([]listItem, 0, len(rows))
	for _, row := range rows {
		title := licenseTableRow(row, totalComponents, 48)
		items = append(items, listItem{
			title:   title,
			details: licenseDetails(row),
		})
	}

	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(interactiveScanViewLicenses),
		controls:       []string{keyHint("/", "search") + " " + keyHint("Enter", "inspect"), render.Style("Group: ", render.Dim) + render.Style("License", render.BgYellow, render.Bold) + render.Style(" | Unique licenses: ", render.Dim) + fmt.Sprintf("%d", len(rows))},
		listTitle:      fmt.Sprintf("Licenses (%d)", len(rows)),
		listHeader:     padRight("License", 22) + padRight("Components", 11) + "Percentage",
		detailTitle:    "License Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; 1-6 switch tabs",
		emptyState:     "No license information found.",
		items:          items,
	}
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
	items := make([]listItem, 0, len(m.findings))
	for _, finding := range m.findings {
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
		controls:       []string{keyHint("/", "search") + " " + keyHint("Enter", "inspect"), render.Style("Filter: ", render.Dim) + render.Style("All", render.BgYellow, render.Bold)},
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
		controls:       []string{keyHint("/", "search") + " " + keyHint("Enter", "toggle") + " " + keyHint("→", "expand") + " " + keyHint("←", "collapse"), render.Style("Mode: ", render.Dim) + render.Style("JSON tree", render.BgYellow, render.Bold) + render.Style(" | Nodes: ", render.Dim) + fmt.Sprintf("%d", sourceNodeCount(m))},
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
		if len(pkgs) > 25 {
			pkgs = pkgs[:25]
		}
		out := make([]listItem, 0, len(pkgs))
		for idx, pkg := range pkgs {
			last := idx == len(pkgs)-1
			tree := prefix + branch(last)
			out = append(out, sourceNode(fmt.Sprintf("%q: {version: %q, ecosystem: %q, licenses: %d, vulnerabilities: %d}", pkg.DisplayName(), valueOrDash(pkg.Version), valueOrDash(pkg.Ecosystem), len(pkg.Licenses), len(pkg.Vulnerabilities)), "package:"+pkg.ID, tree, 2, false, false))
		}
		return out
	case "relationships":
		lines := []string{
			fmt.Sprintf("count: %d", relationshipCount(m.graphValue)),
			fmt.Sprintf("format: %q", "dependency edges"),
		}
		return sourceLeafItems(lines, prefix)
	default:
		return nil
	}
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
	displayedPackages := graphSize(m.graphValue)
	if displayedPackages > 25 {
		displayedPackages = 25
	}
	return 1 + 4 + 5 + len(m.manifests) + displayedPackages + 2
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
		deps, _ := m.graphValue.Dependencies(row.id)
		expanded := m.componentExpanded[row.id]
		if row.relationship == "root" {
			expanded = true
			if _, ok := m.componentExpanded[row.id]; ok {
				expanded = m.componentExpanded[row.id]
			}
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

func (m *scanModel) componentTreeRows(rootID string) []listPackageRow {
	if m == nil || m.graphValue == nil || strings.TrimSpace(rootID) == "" {
		return nil
	}
	rootPkg, ok := m.graphValue.Package(rootID)
	if !ok || rootPkg == nil {
		return nil
	}
	rows := make([]listPackageRow, 0)
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
		return render.Magenta
	case "high":
		return render.Red
	case "medium":
		return render.Yellow
	case "low":
		return render.Cyan
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
			dependents, err := graphValue.Dependents(pkg.ID)
			if err != nil || len(dependents) == 0 {
				continue
			}
			name := packageDisplayName(pkg)
			stats = append(stats, componentStat{name: name, dependents: len(dependents), vulns: vulnCounts[name]})
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
	lines := []string{render.Style(padRight("Component", width-22)+padRight("Deps", 8)+"Vulns", render.Dim)}
	for _, stat := range stats {
		line := padRight(truncateToWidth(stat.name, width-22), width-22) +
			padRight(fmt.Sprintf("%d", stat.dependents), 8) +
			fmt.Sprintf("%d", stat.vulns)
		lines = append(lines, line)
	}
	return lines
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
		dependents, err := graphValue.Dependents(pkg.ID)
		if err == nil && len(dependents) > 0 {
			count++
		}
	}
	return count
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
