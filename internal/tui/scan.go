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

func NewScan(project output.ProjectDescriptor, consolidated sdk.ConsolidatedGraph, graphValue *sdk.Graph, findings []sdk.Finding) *ScanModel {
	return NewScanNavigator("Bomly Interactive Scan", project, consolidated, graphValue, findings)
}

func NewScanNavigator(titlePrefix string, project output.ProjectDescriptor, consolidated sdk.ConsolidatedGraph, graphValue *sdk.Graph, findings []sdk.Finding) *ScanModel {
	return newScanNavigator(titlePrefix, project, consolidated, graphValue, findings, "")
}

func NewExplain(project output.ProjectDescriptor, query string, consolidated sdk.ConsolidatedGraph, graphValue *sdk.Graph, findings []sdk.Finding) *ScanModel {
	return newScanNavigator("Bomly Interactive Explain", project, consolidated, graphValue, findings, query)
}

// WithRegistry attaches the PURL-keyed package registry so the TUI can
// resolve vulnerabilities, licenses, and scorecards by reference. Must be
// called before the model is rendered for the first time when matching-
// stage data should be visible. Safe to pass nil.
func (m *ScanModel) WithRegistry(registry *sdk.PackageRegistry) *ScanModel {
	if m == nil {
		return nil
	}
	m.registry = registry
	if m.shellModel != nil {
		m.Rebuild()
	}
	return m
}

// WithEnrichEnabled records whether the scan requested enrichment so empty
// vulnerability states can distinguish "not requested" from "no matches".
func (m *ScanModel) WithEnrichEnabled(enabled bool) *ScanModel {
	if m == nil {
		return nil
	}
	m.enrichEnabled = enabled
	if m.shellModel != nil {
		m.Rebuild()
	}
	return m
}

// WithReachabilityEnabled records whether the scan requested reachability
// analysis so the conditional interactive filter is only exposed for an
// explicitly enabled scan.
func (m *ScanModel) WithReachabilityEnabled(enabled bool) *ScanModel {
	if m == nil {
		return nil
	}
	m.reachabilityEnabled = enabled
	if m.shellModel != nil {
		m.Rebuild()
	}
	return m
}

func newScanNavigator(titlePrefix string, project output.ProjectDescriptor, consolidated sdk.ConsolidatedGraph, graphValue *sdk.Graph, findings []sdk.Finding, explainQuery string) *ScanModel {
	manifests := manifestRows(consolidated)
	manifestByID := make(map[string]listPackageRow, len(manifests))
	for _, manifest := range manifests {
		manifestByID[manifest.id] = manifest
	}

	model := &ScanModel{
		titlePrefix:           titlePrefix,
		project:               project,
		graphValue:            graphValue,
		explainMode:           strings.Contains(strings.ToLower(titlePrefix), "explain"),
		manifests:             manifests,
		manifestByID:          manifestByID,
		subprojects:           consolidated.Subprojects,
		mode:                  interactiveScanModeManifests,
		allowManifestExit:     len(manifests) > 1,
		findings:              findings,
		explainQuery:          strings.TrimSpace(explainQuery),
		sourceExpanded:        map[string]bool{"root": true},
		componentExpanded:     map[string]bool{},
		vulnerabilityGroup:    "severity",
		vulnerabilityExpanded: map[string]bool{},
		licenseGroup:          "license",
		licenseExpanded:       map[string]bool{},
		findingGroup:          "type",
		findingExpanded:       map[string]bool{},
		postureGroup:          "check",
		postureExpanded:       map[string]bool{},
	}
	if len(manifests) == 1 {
		model.mode = interactiveScanModeComponents
		model.currentManifestID = manifests[0].id
	}
	model.shellModel = newShell(ShellSpec{
		TopBar: model.scanTopBar,
		Tabs: []TabSpec{
			{ID: string(interactiveScanViewOverview), Label: "Overview", Build: model.buildOverviewListModel},
			{ID: string(interactiveScanViewPackages), Label: "Components", Build: model.buildComponentsTreeListModel},
			{ID: string(interactiveScanViewVulns), Label: "Vulnerabilities", Build: model.buildVulnsListModel},
			{ID: string(interactiveScanViewLicenses), Label: "Licenses", Build: model.buildLicensesListModel},
			{ID: string(interactiveScanViewFindings), Label: "Findings", Build: model.buildFindingsListModel},
			{ID: string(interactiveScanViewPosture), Label: "Posture", Build: model.buildPostureListModel},
			{ID: string(interactiveScanViewSource), Label: "Source", Build: model.buildSourceListModel},
		},
		Footer: func() (string, string) {
			return model.scanFooterSummary(), model.scanLegend()
		},
	})
	return model
}

func (m *ScanModel) currentScanView() scanView {
	if m == nil || m.shellModel == nil {
		return interactiveScanViewOverview
	}
	return scanView(m.ActiveTabID())
}

// View overrides shellModel.View so the Overview tab can render its custom
// dashboard layout. All other tabs fall through to the embedded
// shellModel's listModel rendering.
func (m *ScanModel) View(width, height int) string {
	if m == nil || m.shellModel == nil {
		return ""
	}
	if m.currentScanView() == interactiveScanViewOverview && !m.IsSearching() {
		return m.overviewDashboardView(width, height)
	}
	return m.shellModel.View(width, height) //nolint:staticcheck // explicit selector bypasses the View shadow on the embedding model
}

func (m *ScanModel) ToggleSelected() {
	m.toggleSelectedTreeNode()
}

func (m *ScanModel) toggleSelectedTreeNode() {
	if m == nil || m.List() == nil {
		return
	}
	visible := m.List().visibleItemIndices()
	if len(visible) == 0 {
		return
	}
	item := m.List().items[visible[m.List().selectedVisibleIndex(visible)]]
	if m.currentScanView() == interactiveScanViewPackages && item.canOpen && item.key != "" {
		m.componentExpanded[item.key] = !item.expanded
		m.rebuildListPreserveSelection()
		return
	}
	if m.currentScanView() == interactiveScanViewVulns && item.canOpen && item.key != "" {
		m.vulnerabilityExpanded[item.key] = !item.expanded
		m.rebuildListPreserveSelection()
		return
	}
	if m.currentScanView() == interactiveScanViewLicenses && item.canOpen && item.key != "" {
		m.licenseExpanded[item.key] = !item.expanded
		m.rebuildListPreserveSelection()
		return
	}
	if m.currentScanView() == interactiveScanViewFindings && item.canOpen && item.key != "" {
		m.findingExpanded[item.key] = !item.expanded
		m.rebuildListPreserveSelection()
		return
	}
	if m.currentScanView() == interactiveScanViewPosture && item.canOpen && item.key != "" {
		m.postureExpanded[item.key] = !item.expanded
		m.rebuildListPreserveSelection()
		return
	}
	if m.currentScanView() != interactiveScanViewSource {
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

func (m *ScanModel) ExpandSelected() {
	m.setSelectedTreeNode(true)
}

func (m *ScanModel) CollapseSelected() {
	m.setSelectedTreeNode(false)
}

func (m *ScanModel) setSelectedTreeNode(expanded bool) {
	if m == nil || m.List() == nil {
		return
	}
	visible := m.List().visibleItemIndices()
	if len(visible) == 0 {
		return
	}
	item := m.List().items[visible[m.List().selectedVisibleIndex(visible)]]
	if !item.canOpen || item.key == "" || item.expanded == expanded {
		return
	}
	switch m.currentScanView() {
	case interactiveScanViewPackages:
		m.componentExpanded[item.key] = expanded
	case interactiveScanViewVulns:
		m.vulnerabilityExpanded[item.key] = expanded
	case interactiveScanViewLicenses:
		m.licenseExpanded[item.key] = expanded
	case interactiveScanViewFindings:
		m.findingExpanded[item.key] = expanded
	case interactiveScanViewPosture:
		m.postureExpanded[item.key] = expanded
	case interactiveScanViewSource:
		m.sourceExpanded[item.key] = expanded
	default:
		return
	}
	m.rebuildListPreserveSelection()
}

func (m *ScanModel) ExpandAll() {
	m.setAllTreeNodes(true)
}

func (m *ScanModel) CollapseAll() {
	m.setAllTreeNodes(false)
}

func (m *ScanModel) setAllTreeNodes(expanded bool) {
	if m == nil || m.List() == nil {
		return
	}
	if !setVisibleExpansionLayer(m.List(), m.currentTreeExpansionMap(), expanded) {
		return
	}
	m.rebuildListPreserveSelection()
}

func (m *ScanModel) currentTreeExpansionMap() map[string]bool {
	if m == nil {
		return nil
	}
	switch m.currentScanView() {
	case interactiveScanViewPackages:
		return m.componentExpanded
	case interactiveScanViewVulns:
		return m.vulnerabilityExpanded
	case interactiveScanViewLicenses:
		return m.licenseExpanded
	case interactiveScanViewFindings:
		return m.findingExpanded
	case interactiveScanViewPosture:
		return m.postureExpanded
	case interactiveScanViewSource:
		return m.sourceExpanded
	default:
		return nil
	}
}

func (m *ScanModel) CycleGroup() {
	if m == nil {
		return
	}
	switch m.currentScanView() {
	case interactiveScanViewVulns:
		m.vulnerabilityGroup = nextFilterValue(m.vulnerabilityGroup, []string{"severity", "component", "ecosystem"})
	case interactiveScanViewLicenses:
		m.licenseGroup = nextFilterValue(m.licenseGroup, []string{"license", "category", "recognition"})
	case interactiveScanViewFindings:
		m.findingGroup = nextFilterValue(m.findingGroup, []string{"type", "severity", "component", "ecosystem"})
	case interactiveScanViewPosture:
		m.postureGroup = nextFilterValue(m.postureGroup, []string{"check", "repository"})
	default:
		return
	}
	m.rebuildListPreserveSelection()
}

func (m *ScanModel) CycleRelationshipFilter() {
	if m == nil || m.currentScanView() != interactiveScanViewPackages {
		return
	}
	m.relationshipFilter = nextRelationshipFilter(m.relationshipFilter, m.explainMode)
	m.rebuildListPreserveSelection()
}

func (m *ScanModel) CycleScopeFilter() {
	if m == nil || m.currentScanView() != interactiveScanViewPackages {
		return
	}
	m.scopeFilter = nextScopeFilter(m.scopeFilter)
	m.rebuildListPreserveSelection()
}

func (m *ScanModel) CycleSeverityFilter() {
	if m == nil {
		return
	}
	switch m.currentScanView() {
	case interactiveScanViewVulns:
		// always applicable
	case interactiveScanViewPackages:
	default:
		return
	}
	m.severityFilter = nextSeverityFilter(m.severityFilter)
	m.rebuildListPreserveSelection()
}

func (m *ScanModel) CycleEcosystemFilter() {
	if m == nil || m.currentScanView() != interactiveScanViewPackages {
		return
	}
	m.ecosystemFilter = nextFilterValue(m.ecosystemFilter, append([]string{""}, m.componentEcosystemValues()...))
	m.rebuildListPreserveSelection()
}

func (m *ScanModel) CycleReachabilityFilter() {
	if !m.reachabilityFilterAvailable() {
		return
	}
	switch m.currentScanView() {
	case interactiveScanViewPackages, interactiveScanViewVulns:
	default:
		return
	}
	m.reachabilityFilter = nextFilterValue(m.reachabilityFilter, []string{"", string(sdk.ReachabilityReachable), string(sdk.ReachabilityUnreachable)})
	m.rebuildListPreserveSelection()
}

func (m *ScanModel) reachabilityFilterAvailable() bool {
	if m == nil || !m.reachabilityEnabled || m.graphValue == nil || m.registry == nil {
		return false
	}
	for _, pkg := range m.graphValue.Nodes() {
		for _, v := range vulnsForDependency(m.registry, pkg) {
			if v.Reachability != nil {
				return true
			}
		}
	}
	return false
}

func (m *ScanModel) componentEcosystemValues() []string {
	if m == nil || m.graphValue == nil {
		return nil
	}
	values := make(map[string]struct{})
	for _, pkg := range m.graphValue.Nodes() {
		if pkg == nil {
			continue
		}
		values[valueOrDefault(string(pkg.Ecosystem), "unknown")] = struct{}{}
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (m *ScanModel) OpenSelected() {
}

func (m *ScanModel) GoBack() {
	if !m.CanGoBack() {
		return
	}
	m.mode = interactiveScanModeManifests
	m.currentManifestID = ""
	if m.shellModel != nil {
		m.Rebuild()
	}
}

func (m *ScanModel) CanGoBack() bool {
	if m == nil {
		return false
	}
	return m.currentScanView() == interactiveScanViewPackages && m.mode == interactiveScanModeComponents && m.allowManifestExit
}

func (m *ScanModel) rebuildListPreserveSelection() {
	if m == nil || m.shellModel == nil {
		return
	}
	key, title, scrollOffset, detailOffset := "", "", 0, 0
	if prev := m.List(); prev != nil {
		visible := prev.visibleItemIndices()
		if len(visible) > 0 {
			item := prev.items[visible[prev.selectedVisibleIndex(visible)]]
			key = item.key
			title = item.title
		}
		scrollOffset = prev.scrollOffset
		detailOffset = prev.detailOffset
	}
	m.Rebuild()
	next := m.List()
	if next == nil {
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
}

// scanSummaryLines used to inject the top bar + tab strip into each builder's
// listModel.summary. The shared shellModel now owns that chrome, so this
// returns nil; the function exists only so legacy call sites keep compiling.
func (m *ScanModel) scanSummaryLines() []string { return nil }

// scanTopBar is the ShellSpec.TopBar producer for scan/explain/diff-via-scan.
func (m *ScanModel) scanTopBar() string {
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
	return render.Style(" Bomly ", render.BgBrand, render.White, render.Bold) + " " +
		render.Style(m.commandLabel(), render.BgNeutral, render.White, render.Bold) + " " +
		strings.Join(targetParts, render.Style(" | ", render.Dim))
}

func (m *ScanModel) commandLabel() string {
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

func (m *ScanModel) scanStatusLine() string {
	stats := scanStats(m.graphValue, m.registry)
	return render.Style("Components: ", render.Dim) + render.Style(fmt.Sprintf("%d", stats.components), render.Cyan, render.Bold) +
		render.Style(" | Vulns: ", render.Dim) + severityText(fmt.Sprintf("%d", stats.vulnerabilities)) +
		render.Style(" | Licenses: ", render.Dim) + render.Style(fmt.Sprintf("%d", stats.licenses), render.Cyan, render.Bold) +
		render.Style(" | Findings: ", render.Dim) + render.Style(fmt.Sprintf("%d", len(m.findings)), render.Cyan, render.Bold)
}

func (m *ScanModel) scanFooterSummary() string {
	stats := scanStats(m.graphValue, m.registry)
	return fmt.Sprintf("Components: %d | Vulns: %d | Licenses: %d | Findings: %d", stats.components, stats.vulnerabilities, stats.licenses, len(m.findings))
}

func (m *ScanModel) scanLegend() string {
	return strings.Join([]string{
		keyHint("Tab", "switch"),
		keyHint("Enter", "focus details"),
		keyHint("→", "expand"),
		keyHint("←", "collapse"),
		keyHint("]", "expand all"),
		keyHint("[", "collapse all"),
		keyHint("↑/↓", "move"),
		keyHint("q", "quit"),
	}, " ")
}

func (m *ScanModel) scanFooterLines(width int) []string {
	return []string{
		statusBar(m.scanFooterSummary(), width),
		centerLine(m.scanLegend(), width),
	}
}

func (m *ScanModel) componentControlsLine() string {
	parts := []string{keyHint("/", "search"), keyHint("r", "relationship"), keyHint("s", "scope"), keyHint("v", "severity"), keyHint("e", "ecosystem")}
	if m.reachabilityFilterAvailable() {
		parts = append(parts, keyHint("a", "reachability"))
	}
	parts = append(parts, keyHint("]", "expand all"), keyHint("[", "collapse all"))
	return strings.Join(parts, " ")
}

func (m *ScanModel) componentStateLine(extra string) string {
	state := render.Style("Group: ", render.Dim) + render.Style("Dependency", render.BgYellow, render.Bold) +
		render.Style(" | Relationship: ", render.Dim) + render.Style(valueOrDefault(m.relationshipFilter, "All"), render.BgYellow, render.Bold) +
		render.Style(" | Scope: ", render.Dim) + render.Style(valueOrDefault(m.scopeFilter, "All"), render.BgYellow, render.Bold) +
		render.Style(" | Severity: ", render.Dim) + render.Style(valueOrDefault(m.severityFilter, "All"), render.BgYellow, render.Bold) +
		render.Style(" | Ecosystem: ", render.Dim) + render.Style(valueOrDefault(m.ecosystemFilter, "All"), render.BgYellow, render.Bold)
	if m.reachabilityFilterAvailable() {
		state += render.Style(" | Reachability: ", render.Dim) + render.Style(titleCase(valueOrDefault(m.reachabilityFilter, "All")), render.BgYellow, render.Bold)
	}
	if strings.TrimSpace(extra) != "" {
		state += render.Style(" | ", render.Dim) + extra
	}
	return state
}

func (m *ScanModel) buildManifestListModel() *listModel {
	items := make([]listItem, 0, len(m.manifests)+1)
	rootManifests, groups := m.manifestTreeGroups()
	projectMerged := len(rootManifests) == 1
	projectDetailLines := projectDetails(m, packageCount(m.graphValue), packageCount(m.graphValue))
	if projectMerged {
		projectDetailLines = append(projectDetailLines, "")
		projectDetailLines = append(projectDetailLines, manifestDetails(m.graphValue, m.manifests[rootManifests[0]])...)
	}
	items = append(items, listItem{
		title:    m.projectNodeTitle(groups),
		subtitle: "project",
		details:  projectDetailLines,
		key:      "project",
		canOpen:  true,
		expanded: true,
	})

	appendManifest := func(manifestIdx int, ancestorsLast []bool, last bool) {
		manifest := m.manifests[manifestIdx]
		title := fmt.Sprintf("%s (%s, %d components) [%s]", manifest.displayName, manifestEcosystem(m.graphValue, manifest), manifestComponentCount(m.graphValue, manifest.rootID), manifest.id)
		items = append(items, listItem{
			title:    title,
			subtitle: "manifest",
			details:  manifestDetails(m.graphValue, manifest),
			tree:     treeLevelPrefix(ancestorsLast) + treeConnector(last),
			depth:    len(ancestorsLast) + 1,
		})
	}
	var appendGroup func(group *manifestTreeGroup, ancestorsLast []bool, last bool)
	appendGroup = func(group *manifestTreeGroup, ancestorsLast []bool, last bool) {
		if len(group.manifests) == 1 && len(group.children) == 0 {
			// Merged node: the module/subproject and its single manifest are
			// one row, named after the package with the manifest in details.
			manifest := m.manifests[group.manifests[0]]
			items = append(items, listItem{
				title:    fmt.Sprintf("%s (%s, %d components) [%s]", m.manifestRootName(manifest), manifestEcosystem(m.graphValue, manifest), manifestComponentCount(m.graphValue, manifest.rootID), manifest.id),
				subtitle: string(group.kind),
				details:  m.mergedGroupDetails(group, manifest, manifestComponentCount(m.graphValue, manifest.rootID)),
				tree:     treeLevelPrefix(ancestorsLast) + treeConnector(last),
				depth:    len(ancestorsLast) + 1,
			})
			return
		}
		items = append(items, listItem{
			title:    fmt.Sprintf("%s (%d manifests)", group.label, group.manifestCount()),
			subtitle: string(group.kind),
			details:  m.groupDetails(group, 0),
			tree:     treeLevelPrefix(ancestorsLast) + treeConnector(last),
			depth:    len(ancestorsLast) + 1,
		})
		childAncestors := append(append([]bool(nil), ancestorsLast...), last)
		total := len(group.manifests) + len(group.children)
		pos := 0
		for _, index := range group.manifests {
			appendManifest(index, childAncestors, pos == total-1)
			pos++
		}
		for _, child := range group.children {
			appendGroup(child, childAncestors, pos == total-1)
			pos++
		}
	}
	total := len(rootManifests) + len(groups)
	pos := 0
	if projectMerged {
		// The single root manifest lives on the project row itself; only
		// subproject/module rows follow.
		total = len(groups)
	} else {
		for _, index := range rootManifests {
			appendManifest(index, nil, pos == total-1)
			pos++
		}
	}
	for _, group := range groups {
		appendGroup(group, nil, pos == total-1)
		pos++
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
		summary:        m.scanSummaryLines(),
		controls:       []string{m.componentControlsLine() + render.Style(" | Components: ", render.Dim) + fmt.Sprintf("%d", packageCount)},
		listTitle:      fmt.Sprintf("Manifests (%d)", len(m.manifests)),
		detailTitle:    "Manifest Details",
		navigationHelp: interactiveCommonNavigationHelp + "; Enter opens selected manifest",
		filterHelp:     "Use / to search; Enter focuses details; Esc clears search; 1-7 switch tabs",
		emptyState:     "No manifests were found in the dependency graph.",
		items:          items,
		selected:       selected,
	}
}

func (m *ScanModel) buildComponentsTreeListModel() *listModel {
	totalComponents := packageCount(m.graphValue)
	maxSevByID := maxVulnerabilitySeverityByPkgID(m.graphValue, m.registry)
	filteredComponentCount := m.filteredComponentCount(maxSevByID)
	items := make([]listItem, 0, totalComponents+len(m.manifests)+1)
	rootManifests, groups := m.manifestTreeGroups()
	// A directory holding exactly one manifest merges the manifest into its
	// project/module node: the node carries the package name and the manifest
	// details, and components nest directly beneath it.
	projectMerged := len(rootManifests) == 1
	projectKey := "project"
	projectExpanded := expandedValue(m.componentExpanded, projectKey, true)
	projectDetailLines := projectDetails(m, filteredComponentCount, totalComponents)
	if projectMerged {
		projectDetailLines = append(projectDetailLines, "")
		projectDetailLines = append(projectDetailLines, manifestDetails(m.graphValue, m.manifests[rootManifests[0]])...)
	}
	items = append(items, listItem{
		title:    m.projectNodeTitle(groups),
		subtitle: "project",
		details:  projectDetailLines,
		key:      projectKey,
		canOpen:  len(m.manifests) > 0,
		expanded: projectExpanded,
	})

	emitComponents := func(manifest listPackageRow, ancestorsLast []bool, subtreeLast bool, baseDepth int) {
		rows := m.componentTreeRows(manifest.rootID)
		rows = m.filterComponentRows(rows, maxSevByID)
		for _, row := range rows {
			badges := packageBadges(row)
			if sev := maxSevByID[row.id]; sev != "" {
				badges = append([]badge{{label: sev, kind: "severity-" + strings.ToLower(sev)}}, badges...)
			}
			deps, _ := m.graphValue.DirectDependencies(row.id)
			expanded := expandedValue(m.componentExpanded, row.id, false)
			if row.repeated {
				deps = nil
				expanded = false
			}
			items = append(items, listItem{
				title:    row.displayName,
				subtitle: row.relationship,
				badges:   badges,
				details:  componentDetails(m.graphValue, m.registry, row, manifest),
				key:      row.id,
				tree:     componentForestPrefix(ancestorsLast, subtreeLast, row),
				depth:    baseDepth + row.depth,
				canOpen:  len(deps) > 0,
				expanded: expanded,
			})
		}
	}

	emitManifest := func(manifestIdx int, ancestorsLast []bool, last bool) {
		manifest := m.manifests[manifestIdx]
		manifestKey := "manifest:" + manifest.id
		manifestExpanded := expandedValue(m.componentExpanded, manifestKey, false)
		depth := len(ancestorsLast) + 1
		items = append(items, listItem{
			title:    fmt.Sprintf("%s (%s, %d components)", manifest.displayName, manifestEcosystem(m.graphValue, manifest), m.filteredManifestComponentCount(manifest.rootID, maxSevByID)),
			subtitle: "manifest",
			details:  manifestDetails(m.graphValue, manifest),
			key:      manifestKey,
			tree:     treeLevelPrefix(ancestorsLast) + treeConnector(last),
			depth:    depth,
			canOpen:  manifest.rootID != "",
			expanded: manifestExpanded,
		})
		if !manifestExpanded {
			return
		}
		componentAncestors := append(append([]bool(nil), ancestorsLast...), last)
		emitComponents(manifest, componentAncestors, true, depth+1)
	}

	// emitMergedComponents renders the component subtree of an absorbed root:
	// the merged node stands in for the root row, and the root's children
	// render as a top-level forest beneath it.
	emitMergedComponents := func(manifest listPackageRow, ancestorsLast []bool, baseDepth int) {
		rows := m.componentSubtreeRows(manifest.rootID)
		rows = m.filterComponentRows(rows, maxSevByID)
		for _, row := range rows {
			badges := packageBadges(row)
			if sev := maxSevByID[row.id]; sev != "" {
				badges = append([]badge{{label: sev, kind: "severity-" + strings.ToLower(sev)}}, badges...)
			}
			deps, _ := m.graphValue.DirectDependencies(row.id)
			expanded := expandedValue(m.componentExpanded, row.id, false)
			if row.repeated {
				deps = nil
				expanded = false
			}
			items = append(items, listItem{
				title:    row.displayName,
				subtitle: row.relationship,
				badges:   badges,
				details:  componentDetails(m.graphValue, m.registry, row, manifest),
				key:      row.id,
				tree:     treeLevelPrefix(ancestorsLast) + row.tree,
				depth:    baseDepth + row.depth,
				canOpen:  len(deps) > 0,
				expanded: expanded,
			})
		}
	}

	var emitGroup func(group *manifestTreeGroup, ancestorsLast []bool, last bool)

	emitMergedGroup := func(group *manifestTreeGroup, ancestorsLast []bool, last bool) {
		manifest := m.manifests[group.manifests[0]]
		groupExpanded := expandedValue(m.componentExpanded, group.key(), false)
		componentCount := m.filteredManifestComponentCount(manifest.rootID, maxSevByID)
		depth := len(ancestorsLast) + 1
		items = append(items, listItem{
			title:    fmt.Sprintf("%s (%s, %d components) [%s]", m.manifestRootName(manifest), manifestEcosystem(m.graphValue, manifest), componentCount, manifest.id),
			subtitle: string(group.kind),
			details:  m.mergedGroupDetails(group, manifest, componentCount),
			key:      group.key(),
			tree:     treeLevelPrefix(ancestorsLast) + treeConnector(last),
			depth:    depth,
			canOpen:  manifest.rootID != "" && (componentCount > 0 || len(group.children) > 0),
			expanded: groupExpanded,
		})
		if !groupExpanded {
			return
		}
		childAncestors := append(append([]bool(nil), ancestorsLast...), last)
		// Child module nodes first, then the merged node's own dependency
		// forest as the final block — its internal connectors already close
		// the tree.
		for i, child := range group.children {
			emitGroup(child, childAncestors, i == len(group.children)-1 && componentCount == 0)
		}
		emitMergedComponents(manifest, childAncestors, depth)
	}

	emitGroup = func(group *manifestTreeGroup, ancestorsLast []bool, last bool) {
		if len(group.manifests) == 1 {
			emitMergedGroup(group, ancestorsLast, last)
			return
		}
		groupExpanded := expandedValue(m.componentExpanded, group.key(), true)
		componentCount := 0
		for _, index := range group.manifests {
			componentCount += m.filteredManifestComponentCount(m.manifests[index].rootID, maxSevByID)
		}
		title := fmt.Sprintf("%s (%d manifests, %d components)", group.label, group.manifestCount(), componentCount)
		if group.manifestCount() == 1 {
			title = fmt.Sprintf("%s (1 manifest, %d components)", group.label, componentCount)
		}
		items = append(items, listItem{
			title:    title,
			subtitle: string(group.kind),
			details:  m.groupDetails(group, componentCount),
			key:      group.key(),
			tree:     treeLevelPrefix(ancestorsLast) + treeConnector(last),
			depth:    len(ancestorsLast) + 1,
			canOpen:  group.manifestCount() > 0,
			expanded: groupExpanded,
		})
		if !groupExpanded {
			return
		}
		childAncestors := append(append([]bool(nil), ancestorsLast...), last)
		total := len(group.manifests) + len(group.children)
		pos := 0
		for _, index := range group.manifests {
			emitManifest(index, childAncestors, pos == total-1)
			pos++
		}
		for _, child := range group.children {
			emitGroup(child, childAncestors, pos == total-1)
			pos++
		}
	}

	if projectExpanded {
		if projectMerged {
			// The single root manifest merges into the project node:
			// subproject/module nodes first, then the project's own
			// dependency forest as the final block.
			mergedManifest := m.manifests[rootManifests[0]]
			componentCount := m.filteredManifestComponentCount(mergedManifest.rootID, maxSevByID)
			for i, group := range groups {
				emitGroup(group, nil, i == len(groups)-1 && componentCount == 0)
			}
			emitComponents(mergedManifest, nil, true, 1)
		} else {
			total := len(rootManifests) + len(groups)
			pos := 0
			for _, index := range rootManifests {
				emitManifest(index, nil, pos == total-1)
				pos++
			}
			for _, group := range groups {
				emitGroup(group, nil, pos == total-1)
				pos++
			}
		}
	}
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(),
		controls:       []string{m.componentControlsLine(), m.componentStateLine(fmt.Sprintf("Components: %d of %d", filteredComponentCount, totalComponents))},
		listTitle:      fmt.Sprintf("Components (%d)", filteredComponentCount),
		detailTitle:    "Component Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; →/← expand/collapse; Enter focuses details; r relationship; s scope; v severity; 1-7 tabs",
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

// componentForestPrefix renders a component row's tree prefix under its
// parent node. ancestorsLast carries one entry per ancestor level above the
// component subtree (group and manifest nodes), so the continuation bars stay
// correct at any nesting depth. subtreeLast reports whether the component
// subtree is the final child block of its parent — false when sibling nodes
// (e.g. module nodes after a merged project's components) follow it.
func componentForestPrefix(ancestorsLast []bool, subtreeLast bool, row listPackageRow) string {
	prefix := treeLevelPrefix(ancestorsLast)
	if row.depth == 0 {
		return prefix + treeConnector(subtreeLast)
	}
	if subtreeLast {
		return prefix + "   " + row.tree
	}
	return prefix + "│  " + row.tree
}

// projectNodeTitle labels the project root node with manifest and group
// counts.
func (m *ScanModel) projectNodeTitle(groups []*manifestTreeGroup) string {
	manifestWord := "manifests"
	if len(m.manifests) == 1 {
		manifestWord = "manifest"
	}
	title := fmt.Sprintf("%s (%d %s", valueOrDash(m.project.Name), len(m.manifests), manifestWord)
	subprojectCount, moduleCount := 0, 0
	for _, group := range groups {
		switch group.kind {
		case output.ManifestNodeSubproject:
			subprojectCount++
			moduleCount += len(group.children)
		case output.ManifestNodeModule:
			moduleCount++
		}
	}
	if subprojectCount > 0 {
		title += fmt.Sprintf(", %d subprojects", subprojectCount)
	}
	if moduleCount > 0 {
		title += fmt.Sprintf(", %d modules", moduleCount)
	}
	return title + ")"
}

func projectDetails(m *ScanModel, filteredComponents, totalComponents int) []string {
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
	if _, ok := graphValue.Node(rootID); ok {
		count = 1
	}
	return count + len(rows.direct) + len(rows.transitive)
}

func (m *ScanModel) filteredComponentCount(maxSevByID map[string]string) int {
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

func (m *ScanModel) filteredManifestComponentCount(rootID string, maxSevByID map[string]string) int {
	return len(m.filteredManifestComponentRows(rootID, maxSevByID))
}

func (m *ScanModel) filteredManifestComponentRows(rootID string, maxSevByID map[string]string) []listPackageRow {
	if m == nil || m.graphValue == nil || rootID == "" {
		return nil
	}
	rows := componentCountRows(m.graphValue, rootID)
	return m.filterComponentRows(rows, maxSevByID)
}

func (m *ScanModel) filterComponentRows(rows []listPackageRow, maxSevByID map[string]string) []listPackageRow {
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
	if m.reachabilityFilter != "" {
		kept := rows[:0]
		for _, row := range rows {
			pkg, _ := m.graphValue.Node(row.id)
			if packageMatchesReachabilityFilter(vulnsForDependency(m.registry, pkg), m.reachabilityFilter) {
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
		if packageMatchesSeverityFilter(maxSevByID[row.id], m.severityFilter) {
			kept = append(kept, row)
		}
	}
	return kept
}

func packageMatchesReachabilityFilter(vulns []sdk.Vulnerability, filter string) bool {
	if filter == "" {
		return true
	}
	hasReachable := false
	hasMatching := false
	for _, v := range vulns {
		if v.Reachability == nil {
			continue
		}
		status := string(v.Reachability.Status)
		if status == string(sdk.ReachabilityReachable) {
			hasReachable = true
		}
		if status == filter {
			hasMatching = true
		}
	}
	switch filter {
	case string(sdk.ReachabilityReachable):
		return hasReachable
	case string(sdk.ReachabilityUnreachable):
		// Mixed packages (with at least one reachable vuln) are excluded from
		// the unreachable filter so users can drill into truly-unreachable
		// dependencies without noise.
		return hasMatching && !hasReachable
	default:
		return hasMatching
	}
}

func packageMatchesSeverityFilter(maxSeverity, filter string) bool {
	switch strings.ToLower(strings.TrimSpace(filter)) {
	case "":
		return true
	case "any":
		return strings.TrimSpace(maxSeverity) != ""
	case "none":
		return strings.TrimSpace(maxSeverity) == ""
	default:
		return strings.EqualFold(maxSeverity, filter)
	}
}

func vulnerabilityMatchesSeverityFilter(vulnerability sdk.Vulnerability, filter string) bool {
	switch strings.ToLower(strings.TrimSpace(filter)) {
	case "", "any":
		return true
	case "none":
		return false
	default:
		return strings.EqualFold(string(vulnerability.ParsedSeverity), filter)
	}
}

func vulnerabilityReachabilityBadge(vulnerability sdk.Vulnerability) (badge, bool) {
	if vulnerability.Reachability == nil {
		return badge{}, false
	}
	switch vulnerability.Reachability.Status {
	case sdk.ReachabilityReachable:
		return badge{label: string(sdk.ReachabilityReachable), kind: "reachability-reachable"}, true
	case sdk.ReachabilityUnreachable:
		return badge{label: string(sdk.ReachabilityUnreachable), kind: "reachability-unreachable"}, true
	default:
		return badge{}, false
	}
}

func componentCountRows(graphValue *sdk.Graph, rootID string) []listPackageRow {
	if graphValue == nil || strings.TrimSpace(rootID) == "" {
		return nil
	}
	rootPkg, ok := graphValue.Node(rootID)
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
	pkg, ok := graphValue.Node(row.rootID)
	if !ok || pkg == nil {
		return "unknown"
	}
	return valueOrDefault(string(pkg.Ecosystem), "unknown")
}

func (m *ScanModel) buildOverviewListModel() *listModel {
	vulnerabilities := packageVulnerabilityRows(m.graphValue, m.registry)
	stats := scanStats(m.graphValue, m.registry)
	items := []listItem{
		{
			title:    "Target Information",
			subtitle: "overview",
			details: []string{
				render.Style("Target", render.Bold, render.Cyan),
				render.Style("  Name: ", render.Dim) + valueOrDash(m.project.Name),
				render.Style("  Path: ", render.Dim) + valueOrDash(m.project.Path),
				render.Style("  Ecosystem: ", render.Dim) + valueOrDash(string(m.project.Ecosystem)),
				render.Style("  Package manager: ", render.Dim) + valueOrDash(m.project.PackageManager.Name()),
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
			details:  severityDistributionDetails("Vulnerability Severity", vulnerabilities, m.reachabilityEnabled),
		},
		{
			title:    "Components by Ecosystem",
			subtitle: "distribution",
			details:  distributionDetails("Ecosystem Distribution", stats.ecosystems),
		},
		{
			title:    "Components by License",
			subtitle: "distribution",
			details:  licenseDistributionDetails(m.graphValue, m.registry),
		},
		{
			title:    "Top Vulnerable Components",
			subtitle: "top",
			details:  topVulnerableComponentDetails(m.graphValue, m.registry),
		},
		{
			title:    "Top Depended-On Components",
			subtitle: "top",
			details:  topDependedOnDetails(m.graphValue),
		},
	}
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(),
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Tab or 1-7 switches tabs; e export; ? help",
		emptyState:     "No scan overview is available.",
		items:          items,
	}
}

func (m *ScanModel) overviewDashboardView(width, height int) string {
	if width < 80 || height < 22 {
		return m.shellModel.View(width, height) //nolint:staticcheck // explicit selector bypasses the View shadow on the embedding model
	}
	var lines []string
	for _, summaryLine := range m.shellSummaryLines() {
		lines = append(lines, truncateToWidth(summaryLine, width))
	}
	footerLines := m.scanFooterLines(width)
	bodyHeight := height - len(lines) - len(footerLines)
	if bodyHeight < 12 {
		return m.shellModel.View(width, height) //nolint:staticcheck // explicit selector bypasses the View shadow on the embedding model
	}

	vulnerabilities := packageVulnerabilityRows(m.graphValue, m.registry)
	stats := scanStats(m.graphValue, m.registry)
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
			severityCardLine(vulnerabilities, "critical", m.reachabilityEnabled),
			severityCardLine(vulnerabilities, "high", m.reachabilityEnabled),
			severityCardLine(vulnerabilities, "medium", m.reachabilityEnabled),
			severityCardLine(vulnerabilities, "low", m.reachabilityEnabled),
		), summaryWidth, cardHeight, render.Red),
		boxView("Licenses", summaryCountCardLines(stats.licenses, "Unique Licenses", summaryWidth-2, render.Yellow,
			fmt.Sprintf("%d unknown", unknownLicenseCount(m.graphValue, m.registry)),
			fmt.Sprintf("%d unrecognized", unrecognizedLicenseCount(m.graphValue, m.registry)),
		), summaryWidth, cardHeight, render.Yellow),
		boxView("Target", []string{
			render.Style("Name: ", render.Dim) + valueOrDash(m.project.Name),
			render.Style("Type: ", render.Dim) + targetKindLabel(m.project),
			render.Style("Ref: ", render.Dim) + valueOrDash(m.project.TargetRef),
			render.Style("Path: ", render.Dim) + valueOrDash(m.project.Path),
			render.Style("Ecosystem: ", render.Dim) + valueOrDash(string(m.project.Ecosystem)),
			render.Style("Package manager: ", render.Dim) + valueOrDash(m.project.PackageManager.Name()),
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
	topVuln := topVulnerableComponentStats(m.graphValue, m.registry, 8)
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
		boxView("License Distribution", coloredDistributionLines(groupedLicenseCounts(m.graphValue, m.registry, 10), stats.components, 10, rightWidth-2), rightWidth, rightA, render.Yellow),
		boxView("Vulnerability Severity", severityDistributionLines(vulnerabilities, rightWidth-2, m.reachabilityEnabled), rightWidth, rightB, render.Red),
		boxView(fmt.Sprintf("Top Vulnerable Components (%d)", vulnerableComponentTotal(m.graphValue, m.registry)), topVulnerableTableLines(topVuln, rightWidth-2), rightWidth, rightC, render.Red),
	)
	lines = append(lines, joinColumns(leftContent, rightContent, leftWidth, rightWidth)...)
	lines = append(lines, footerLines...)
	return strings.Join(lines, "\n")
}

func (m *ScanModel) buildVulnsListModel() *listModel {
	all := packageVulnerabilityRows(m.graphValue, m.registry)

	// Apply severity and reachability filters.
	filtered := all
	if m.severityFilter != "" || m.reachabilityFilter != "" {
		filtered = make([]packageVulnerabilityRow, 0, len(all))
		for _, row := range all {
			if !vulnerabilityMatchesSeverityFilter(row.vulnerability, m.severityFilter) {
				continue
			}
			if m.reachabilityFilter != "" && (row.vulnerability.Reachability == nil || string(row.vulnerability.Reachability.Status) != m.reachabilityFilter) {
				continue
			}
			filtered = append(filtered, row)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		ri, rj := severityRank(string(filtered[i].vulnerability.ParsedSeverity)), severityRank(string(filtered[j].vulnerability.ParsedSeverity))
		if ri != rj {
			return ri < rj
		}
		return filtered[i].vulnerability.ID < filtered[j].vulnerability.ID
	})

	items := m.vulnerabilityItems(filtered)
	emptyState := "No vulnerabilities match the selected filters."
	if len(all) == 0 {
		if m.enrichEnabled {
			emptyState = "No enriched vulnerabilities matched this scan."
		} else {
			emptyState = "No enriched vulnerabilities found. Run with --enrich to populate vulnerability data."
		}
	}

	return &listModel{
		title:       fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:     m.scanSummaryLines(),
		controls:    []string{m.vulnerabilityControlsLine(), m.vulnerabilityStateLine(len(filtered), len(all))},
		listTitle:   fmt.Sprintf("Vulnerabilities (%d)", len(filtered)),
		listHeader:  "Vulnerability ID / Group",
		detailTitle: "Vulnerability Details",
		topPanels: []listPanel{
			{title: "Severity Summary", lines: vulnerabilitySummaryLines(all), color: render.Red, weight: 1},
			{title: "Top Affected", lines: topAffectedLines(all, 5, 140), buildLines: func(width int) []string {
				return topAffectedLines(all, 5, width)
			}, color: render.Green, weight: 2},
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter focuses details; Esc clears search; v cycles severity filter; g groups vulnerabilities; 1-7 switch tabs",
		emptyState:     emptyState,
		items:          items,
	}
}

func (m *ScanModel) vulnerabilityItems(vulnerabilities []packageVulnerabilityRow) []listItem {
	group := strings.TrimSpace(m.vulnerabilityGroup)
	if group == "" {
		group = "severity"
	}
	groups := make(map[string][]packageVulnerabilityRow)
	for _, vulnerability := range vulnerabilities {
		key := vulnerabilityGroupKey(vulnerability, group)
		groups[key] = append(groups[key], vulnerability)
	}
	keys := sortedVulnerabilityGroupKeys(groups)
	items := make([]listItem, 0, len(vulnerabilities)+len(keys))
	for _, key := range keys {
		groupKey := group + ":" + key
		expanded := expandedValue(m.vulnerabilityExpanded, groupKey, true)
		groupVulnerabilities := groups[key]
		items = append(items, listItem{
			title:    fmt.Sprintf("%s (%d)", key, len(groupVulnerabilities)),
			subtitle: "group",
			details:  vulnerabilityGroupDetails(key, group, groupVulnerabilities),
			key:      groupKey,
			canOpen:  true,
			expanded: expanded,
		})
		if !expanded {
			continue
		}
		for idx, vulnerability := range groupVulnerabilities {
			title := vulnerability.vulnerability.ID
			if group != "component" {
				if pkgName := vulnerabilityPackageName(vulnerability); pkgName != "" {
					title += "  " + pkgName
				}
			}
			var badges []badge
			if group != "severity" {
				badges = append(badges, badge{label: string(vulnerability.vulnerability.ParsedSeverity), kind: "severity-" + strings.ToLower(string(vulnerability.vulnerability.ParsedSeverity))})
			}
			if m.reachabilityEnabled {
				if reachabilityBadge, ok := vulnerabilityReachabilityBadge(vulnerability.vulnerability); ok {
					badges = append(badges, reachabilityBadge)
				}
			}
			items = append(items, listItem{
				title:   title,
				badges:  badges,
				details: vulnerabilityDetails(vulnerability),
				tree:    treePrefix(nil, idx == len(groupVulnerabilities)-1, 1),
				depth:   1,
			})
		}
	}
	return items
}

func sortedVulnerabilityGroupKeys(groups map[string][]packageVulnerabilityRow) []string {
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

func vulnerabilityGroupKey(row packageVulnerabilityRow, group string) string {
	switch group {
	case "severity":
		return titleCase(valueOrDefault(string(row.vulnerability.ParsedSeverity), "unknown"))
	case "ecosystem":
		if row.pkg != nil {
			return valueOrDefault(string(row.pkg.Ecosystem), "unknown")
		}
		return "unknown"
	default:
		return valueOrDefault(vulnerabilityPackageName(row), "unknown component")
	}
}

func vulnerabilityPackageName(row packageVulnerabilityRow) string {
	if row.pkg == nil {
		return ""
	}
	return packageDisplayName(row.pkg)
}

func (m *ScanModel) vulnerabilityControlsLine() string {
	parts := []string{keyHint("/", "search"), keyHint("g", "group"), keyHint("v", "severity")}
	if m.reachabilityFilterAvailable() {
		parts = append(parts, keyHint("a", "reachability"))
	}
	parts = append(parts, keyHint("]", "expand all"), keyHint("[", "collapse all"))
	return strings.Join(parts, " ")
}

func (m *ScanModel) vulnerabilityStateLine(showing, total int) string {
	state := render.Style("Filter: ", render.Dim) + render.Style(valueOrDefault(m.severityFilter, "All"), render.BgYellow, render.Bold) +
		render.Style(" | Group: ", render.Dim) + render.Style(valueOrDefault(m.vulnerabilityGroup, "severity"), render.BgYellow, render.Bold) +
		render.Style(" | Showing: ", render.Dim) + fmt.Sprintf("%d/%d", showing, total)
	if m.reachabilityFilterAvailable() {
		state += render.Style(" | Reachability: ", render.Dim) + render.Style(titleCase(valueOrDefault(m.reachabilityFilter, "All")), render.BgYellow, render.Bold)
	}
	return state
}

func vulnerabilitySummaryLines(vulnerabilities []packageVulnerabilityRow) []string {
	counts := severityDistribution(vulnerabilities)
	affected := make(map[string]struct{})
	for _, vulnerability := range vulnerabilities {
		if name := vulnerabilityPackageName(vulnerability); name != "" {
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

func topAffectedLines(vulnerabilities []packageVulnerabilityRow, limit, width int) []string {
	counts := make(map[string]int)
	for _, vulnerability := range vulnerabilities {
		if name := vulnerabilityPackageName(vulnerability); name != "" {
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
	maxVal := maxCount(counts)
	lines := make([]string, 0, len(keys))
	for idx, key := range keys {
		if width < 32 {
			width = 32
		}
		labelWidth := width / 3
		if labelWidth < 18 {
			labelWidth = 18
		}
		if labelWidth > 34 {
			labelWidth = 34
		}
		suffix := fmt.Sprintf(" %d", counts[key])
		barWidth := width - labelWidth - 1 - len(suffix) - 2
		if barWidth < 10 {
			barWidth = 10
			labelWidth = width - barWidth - 1 - len(suffix) - 2
			if labelWidth < 8 {
				labelWidth = 8
				barWidth = width - labelWidth - 1 - len(suffix) - 2
				if barWidth < 1 {
					barWidth = 1
				}
			}
		}
		lines = append(lines, padRight(truncateToWidth(key, labelWidth), labelWidth)+render.Style(" ", render.Dim)+coloredBarLine(counts[key], maxVal, barWidth, paletteColor(idx))+suffix)
	}
	return lines
}

func vulnerabilityGroupDetails(key, group string, vulnerabilities []packageVulnerabilityRow) []string {
	lines := []string{
		render.Style("Group", render.Bold, render.Cyan),
		"",
		render.Style("  Name: ", render.Dim) + key,
		render.Style("  Grouping: ", render.Dim) + group,
		render.Style("  Vulnerabilities: ", render.Dim) + fmt.Sprintf("%d", len(vulnerabilities)),
		"",
		render.Style(fmt.Sprintf("CVEs (%d)", len(vulnerabilities)), render.Bold, render.Magenta),
	}
	for _, vulnerability := range vulnerabilities {
		lines = append(lines, render.Style("  - ", render.Dim)+vulnerability.vulnerability.ID+" "+valueOrDash(vulnerability.vulnerability.Title))
	}
	return lines
}

func vulnerabilityDetails(row packageVulnerabilityRow) []string {
	vulnerability := row.vulnerability
	packageID, packageVersion, packageEcosystem, packagePURL := "", "", "", ""
	if row.pkg != nil {
		packageID = row.pkg.ID
		packageVersion = row.pkg.Version
		packageEcosystem = string(row.pkg.Ecosystem)
		packagePURL = row.pkg.PURL
	}
	lines := []string{
		render.Style("Vulnerability", render.Bold, render.Cyan),
		"",
		render.Style("  ID: ", render.Dim) + valueOrDash(vulnerability.ID),
		render.Style("  Severity: ", render.Dim) + severityText(string(vulnerability.ParsedSeverity)),
		render.Style("  Severity source: ", render.Dim) + valueOrDash(vulnerability.SeveritySource),
		render.Style("  Source: ", render.Dim) + valueOrDash(vulnerability.Source),
		render.Style("  Namespace: ", render.Dim) + valueOrDash(vulnerability.Namespace),
		render.Style("  Data source: ", render.Dim) + valueOrDash(vulnerability.DataSource),
		render.Style("  Package: ", render.Dim) + valueOrDash(vulnerabilityPackageName(row)),
		render.Style("  Package ID: ", render.Dim) + valueOrDash(packageID),
		render.Style("  Installed version: ", render.Dim) + valueOrDash(packageVersion),
		render.Style("  Ecosystem: ", render.Dim) + valueOrDash(packageEcosystem),
		render.Style("  PURL: ", render.Dim) + valueOrDash(packagePURL),
		render.Style("  Title: ", render.Dim) + valueOrDash(vulnerability.Title),
		render.Style("  KEV exploited: ", render.Dim) + fmt.Sprintf("%t", vulnerability.KEVExploited),
		render.Style("  Exploitability: ", render.Dim) + valueOrDash(exploitabilityLine(vulnerability.KEVExploited, vulnerability.KnownExploited, vulnerability.RiskScore)),
		render.Style("  Risk score: ", render.Dim) + valueOrDash(formatFloat(vulnerability.RiskScore)),
		"",
		render.Style("Description", render.Bold, render.Magenta),
		"",
		render.Style("  ", render.Dim) + valueOrDash(vulnerability.Details),
		"",
		render.Style("Versions", render.Bold, render.Magenta),
		"",
		render.Style("  Affected: ", render.Dim) + valueOrDash(vulnerability.AffectedVersionRange),
		render.Style("  Fixed in: ", render.Dim) + valueOrDash(vulnerability.FixedIn),
		render.Style("  Fix state: ", render.Dim) + valueOrDash(string(vulnerability.FixState)),
		render.Style("  Fixed versions: ", render.Dim) + valueOrDash(strings.Join(vulnerability.FixedVersions, ", ")),
		"",
	}

	appendStringSection := func(title string, values []string) {
		lines = append(lines, render.Style(fmt.Sprintf("%s (%d)", title, len(values)), render.Bold, render.Magenta))
		if len(values) == 0 {
			lines = append(lines, render.Style("  (none)", render.Dim), "")
			return
		}
		lines = append(lines, indentLines(values)...)
		lines = append(lines, "")
	}

	appendStringSection("Aliases", vulnerability.Aliases)

	lines = append(lines, render.Style(fmt.Sprintf("EPSS (%d)", len(vulnerability.EPSS)), render.Bold, render.Magenta))
	if len(vulnerability.EPSS) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, epss := range vulnerability.EPSS {
			parts := []string{
				fmt.Sprintf("score %.3f", epss.EPSS),
				fmt.Sprintf("percentile %.3f", epss.Percentile),
				epss.CVE,
				epss.Date,
			}
			lines = append(lines, render.Style("  - ", render.Dim)+strings.Join(nonEmptyStrings(parts), " | "))
		}
	}
	lines = append(lines, "", render.Style(fmt.Sprintf("CWEs (%d)", len(vulnerability.CWEs)), render.Bold, render.Magenta))
	if len(vulnerability.CWEs) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, cwe := range vulnerability.CWEs {
			lines = append(lines, render.Style("  - ", render.Dim)+strings.Join(nonEmptyStrings([]string{cwe.ID, cwe.Source, cwe.Type, cwe.CVE}), " | "))
		}
	}
	lines = append(lines, "", render.Style(fmt.Sprintf("Known Exploited (%d)", len(vulnerability.KnownExploited)), render.Bold, render.Magenta))
	if len(vulnerability.KnownExploited) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, ke := range vulnerability.KnownExploited {
			headParts := []string{ke.CVE, ke.VendorProject, ke.Product}
			if ke.DateAdded != "" {
				headParts = append(headParts, "added "+ke.DateAdded)
			}
			if ke.DueDate != "" {
				headParts = append(headParts, "due "+ke.DueDate)
			}
			head := strings.Join(nonEmptyStrings(headParts), " | ")
			lines = append(lines, render.Style("  - ", render.Dim)+valueOrDash(head))
			if ke.KnownRansomwareCampaignUse != "" {
				lines = append(lines, render.Style("    ransomware: ", render.Dim)+ke.KnownRansomwareCampaignUse)
			}
			if ke.RequiredAction != "" {
				lines = append(lines, render.Style("    action: ", render.Dim)+ke.RequiredAction)
			}
			if ke.Notes != "" {
				lines = append(lines, render.Style("    notes: ", render.Dim)+ke.Notes)
			}
			if len(ke.CWEs) > 0 {
				lines = append(lines, render.Style("    cwes: ", render.Dim)+strings.Join(nonEmptyStrings(ke.CWEs), ", "))
			}
			if len(ke.URLs) > 0 {
				lines = append(lines, render.Style("    urls: ", render.Dim)+strings.Join(nonEmptyStrings(ke.URLs), ", "))
			}
		}
	}
	lines = append(lines, "", render.Style(fmt.Sprintf("References (%d)", len(vulnerability.References)), render.Bold, render.Magenta))
	if len(vulnerability.References) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, ref := range vulnerability.References {
			lines = append(lines, render.Style("  - ", render.Dim)+strings.Join(nonEmptyStrings([]string{string(ref.Type), ref.URL}), " | "))
		}
	}
	lines = append(lines, "", render.Style(fmt.Sprintf("Fix Availability (%d)", len(vulnerability.FixAvailable)), render.Bold, render.Magenta))
	if len(vulnerability.FixAvailable) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, fix := range vulnerability.FixAvailable {
			lines = append(lines, render.Style("  - ", render.Dim)+strings.Join(nonEmptyStrings([]string{fix.Version, fix.Date, string(fix.Kind)}), " "))
		}
	}

	lines = append(lines, "", render.Style(fmt.Sprintf("Affected Symbols (%d)", len(vulnerability.AffectedSymbols)), render.Bold, render.Magenta))
	if len(vulnerability.AffectedSymbols) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, symbol := range vulnerability.AffectedSymbols {
			lines = append(lines, render.Style("  - ", render.Dim)+strings.Join(nonEmptyStrings([]string{symbol.Symbol, string(symbol.Kind), symbol.Package, symbol.Module}), " | "))
		}
	}
	lines = append(lines, "")
	appendStringSection("CPEs", vulnerability.CPEs)
	appendStringSection("Reasons", vulnerability.Reasons)
	return lines
}

func (m *ScanModel) buildLicensesListModel() *listModel {
	rows := licenseRows(m.graphValue, m.registry)
	totalComponents := graphSize(m.graphValue)
	items := m.licenseItems(rows, totalComponents)

	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(),
		controls:       []string{keyHint("/", "search") + " " + keyHint("g", "group") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all"), render.Style("Group: ", render.Dim) + render.Style(valueOrDefault(m.licenseGroup, "license"), render.BgYellow, render.Bold) + render.Style(" | Unique licenses: ", render.Dim) + fmt.Sprintf("%d", len(rows))},
		listTitle:      fmt.Sprintf("Licenses (%d)", len(rows)),
		listHeader:     padRight("License", 22) + padRight("Components", 11) + "Percentage",
		detailTitle:    "License Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter focuses details; Esc clears search; 1-7 switch tabs",
		emptyState:     "No license information found.",
		items:          items,
	}
}

func (m *ScanModel) licenseItems(rows []licenseRow, totalComponents int) []listItem {
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

func (m *ScanModel) buildFindingsListModel() *listModel {
	items := m.findingItems(m.findings)
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(),
		controls:       []string{keyHint("/", "search") + " " + keyHint("g", "group") + " " + keyHint("Enter", "focus details") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all"), render.Style("Group: ", render.Dim) + render.Style(valueOrDefault(m.findingGroup, "type"), render.BgYellow, render.Bold) + render.Style(" | Filter: ", render.Dim) + render.Style("All", render.BgYellow, render.Bold)},
		listTitle:      fmt.Sprintf("Findings (%d)", len(m.findings)),
		listHeader:     "Finding",
		detailTitle:    "Finding Details",
		topPanels:      []listPanel{{title: "Findings Summary", lines: findingSummaryLines(m.findings), color: render.Red, weight: 1}},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter focuses details; Esc clears search; 1-7 switch tabs",
		emptyState:     "No findings found. Run with --audit to evaluate available vulnerability data.",
		items:          items,
	}
}

// buildPostureListModel produces the listModel for the Posture tab.
// Conventions match Vulnerabilities/Licenses: a top-panels pair shows
// distribution + top failing checks across the dependency set, the main
// list lines up one row per source repository (worst-scoring first), and
// the details pane shows the full Scorecard breakdown plus the packages
// that resolved to the selected repo. The `g` key cycles between two
// grouping axes: "check" (default) and "repository".
func (m *ScanModel) buildPostureListModel() *listModel {
	rows := postureRowsFromGraph(m.graphValue, m.registry)
	repoWidth := 40
	if len(rows) > 0 {
		maxRepo := 0
		for _, row := range rows {
			if len(row.repository) > maxRepo {
				maxRepo = len(row.repository)
			}
		}
		repoWidth = maxRepo
		if repoWidth > 32 {
			repoWidth = 32
		}
		if repoWidth < 24 {
			repoWidth = 24
		}
	}

	group := valueOrDefault(m.postureGroup, "check")
	var items []listItem
	var listTitle, listHeader string
	switch group {
	case "check":
		checkRepoWidth := repoWidth
		if checkRepoWidth > 24 {
			checkRepoWidth = 24
		}
		items, listTitle, listHeader = m.postureItemsByCheck(rows, checkRepoWidth)
	default:
		items = m.postureItemsByRepository(rows, repoWidth)
		listTitle = fmt.Sprintf("Repositories (%d)", len(rows))
		listHeader = padRight("Repository", repoWidth) + "  " + padRight("Score", 8) + "Packages"
	}

	emptyState := "No Scorecard data attached. Run with --enrich --matchers +scorecard to populate posture data."
	if m.enrichEnabled && len(rows) == 0 {
		emptyState = "Enrichment ran without Scorecard. Re-run with --matchers +scorecard to populate posture data."
	}

	return &listModel{
		title:       fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:     m.scanSummaryLines(),
		controls:    []string{m.postureControlsLine(), m.postureStateLine(group, len(rows))},
		listTitle:   listTitle,
		listHeader:  listHeader,
		detailTitle: "Repository Posture",
		topPanels: []listPanel{
			{title: "Posture Summary", lines: postureSummaryLines(rows), color: render.Yellow, weight: 1},
			{title: "Top Failing Checks", lines: postureTopFailingLines(rows, 140), buildLines: func(width int) []string {
				return postureTopFailingLines(rows, width)
			}, color: render.Red, weight: 2},
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; g cycles group (repository/check); Enter focuses details; 1-7 switch tabs",
		emptyState:     emptyState,
		items:          items,
	}
}

// postureItemsByRepository builds the default flat list of repositories.
func (m *ScanModel) postureItemsByRepository(rows []postureRow, repoWidth int) []listItem {
	items := make([]listItem, 0, len(rows))
	for _, row := range rows {
		band := postureScoreBand(row.card.AggregateScore)
		items = append(items, listItem{
			title:   postureListTitle(row, repoWidth),
			badges:  []badge{{label: strings.ToUpper(band), kind: postureBandBadgeKind(band)}},
			details: postureRowDetails(row),
		})
	}
	return items
}

// postureItemsByCheck builds the by-check view: one expandable group
// header per check name (worst failure rate first), under which the
// affected repositories appear as child rows.
func (m *ScanModel) postureItemsByCheck(rows []postureRow, repoWidth int) ([]listItem, string, string) {
	groups := postureCheckGroups(rows)
	items := make([]listItem, 0, len(rows)+len(groups))
	for _, group := range groups {
		groupKey := "check:" + group.Name
		expanded := expandedValue(m.postureExpanded, groupKey, true)
		items = append(items, listItem{
			title:    postureCheckGroupTitle(group),
			subtitle: "group",
			details:  postureCheckGroupDetails(group),
			key:      groupKey,
			canOpen:  true,
			expanded: expanded,
		})
		if !expanded {
			continue
		}
		all := make([]postureCheckGroupRow, 0, len(group.FailingRepos)+len(group.InconclusiveRepos)+len(group.PassingRepos))
		all = append(all, group.FailingRepos...)
		all = append(all, group.InconclusiveRepos...)
		all = append(all, group.PassingRepos...)
		for idx, r := range all {
			items = append(items, listItem{
				title:   postureCheckGroupRowTitle(r, repoWidth),
				details: postureCheckGroupRowDetails(group, r),
				tree:    treePrefix(nil, idx == len(all)-1, 1),
				depth:   1,
			})
		}
	}
	listTitle := fmt.Sprintf("Checks (%d)", len(groups))
	listHeader := padRight("Check / Repository", repoWidth+6) + "  " + padRight("Score", 8) + "Notes"
	return items, listTitle, listHeader
}

func (m *ScanModel) postureControlsLine() string {
	return keyHint("/", "search") + " " + keyHint("g", "group") + " " + keyHint("Enter", "focus details") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all")
}

func (m *ScanModel) postureStateLine(group string, total int) string {
	return render.Style("Group: ", render.Dim) + render.Style(group, render.BgYellow, render.Bold) +
		render.Style(" | Repositories: ", render.Dim) + render.Style(fmt.Sprintf("%d", total), render.BgYellow, render.Bold) +
		render.Style(" | Source: ", render.Dim) + render.Style("api.scorecard.dev", render.BgYellow, render.Bold)
}

func (m *ScanModel) findingItems(findings []sdk.Finding) []listItem {
	group := valueOrDefault(m.findingGroup, "type")
	grouped := make(map[string][]sdk.Finding)
	for _, finding := range findings {
		grouped[m.findingGroupKey(finding, group)] = append(grouped[m.findingGroupKey(finding, group)], finding)
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
				badges:   []badge{{label: string(finding.Severity), kind: "severity-" + strings.ToLower(string(finding.Severity))}},
				details:  m.findingDetails(finding),
				tree:     treePrefix(nil, idx == len(groupFindings)-1, 1),
				depth:    1,
			})
		}
	}
	return items
}

func (m *ScanModel) findingGroupKey(finding sdk.Finding, group string) string {
	switch group {
	case "severity":
		return titleCase(valueOrDefault(string(finding.Severity), "n/a"))
	case "component":
		return valueOrDefault(m.findingPackageName(finding), "unknown component")
	case "ecosystem":
		if m != nil && m.registry != nil && finding.PackageRef != "" {
			if pkg, ok := m.registry.Get(finding.PackageRef); ok && pkg != nil && pkg.Ecosystem != "" {
				return string(pkg.Ecosystem)
			}
		}
		return "unknown"
	default:
		return titleCase(string(finding.Kind))
	}
}

func (m *ScanModel) findingPackageName(finding sdk.Finding) string {
	if m != nil && m.registry != nil && finding.PackageRef != "" {
		if pkg, ok := m.registry.Get(finding.PackageRef); ok && pkg != nil && pkg.Name != "" {
			if pkg.Version != "" {
				return pkg.Name + "@" + pkg.Version
			}
			return pkg.Name
		}
	}
	return finding.PackageRef
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

func (m *ScanModel) findingDetails(finding sdk.Finding) []string {
	pkgDisplay := m.findingPackageName(finding)
	details := []string{
		render.Style("Finding", render.Bold, render.Cyan),
		"",
		render.Style("  ID: ", render.Dim) + valueOrDash(finding.ID),
		render.Style("  Kind: ", render.Dim) + valueOrDash(string(finding.Kind)),
		render.Style("  Severity: ", render.Dim) + severityText(string(finding.Severity)),
		render.Style("  Package: ", render.Dim) + valueOrDash(pkgDisplay),
		render.Style("  Title: ", render.Dim) + valueOrDash(finding.Title),
		render.Style("  Source: ", render.Dim) + valueOrDash(finding.Source),
	}
	if m != nil && m.registry != nil && finding.PackageRef != "" {
		if pkg, ok := m.registry.Get(finding.PackageRef); ok && pkg != nil {
			vulnID := finding.VulnerabilityID
			if vulnID == "" {
				vulnID = finding.ID
			}
			for i := range pkg.Vulnerabilities {
				v := &pkg.Vulnerabilities[i]
				if v.ID != vulnID {
					matched := false
					for _, alias := range v.Aliases {
						if alias == vulnID {
							matched = true
							break
						}
					}
					if !matched {
						continue
					}
				}
				if v.FixedIn != "" {
					details = append(details, render.Style("  Fixed in: ", render.Dim)+v.FixedIn)
				}
				if v.FixState != "" {
					details = append(details, render.Style("  Fix state: ", render.Dim)+string(v.FixState))
				}
				if v.KEVExploited {
					details = append(details, render.Style("  KEV: ", render.Dim)+"yes")
				}
				if len(v.EPSS) > 0 {
					details = append(details, render.Style("  EPSS: ", render.Dim)+fmt.Sprintf("%.2f", v.EPSS[0].EPSS))
				}
				if len(v.CWEs) > 0 {
					ids := make([]string, 0, len(v.CWEs))
					for _, c := range v.CWEs {
						ids = append(ids, c.ID)
					}
					details = append(details, render.Style("  CWEs: ", render.Dim)+strings.Join(ids, ", "))
				}
				if v.Reachability != nil {
					details = append(details, render.Style("  Reachability: ", render.Dim)+string(v.Reachability.Status))
				}
				if v.Details != "" {
					details = append(details, render.Style("  Description: ", render.Dim)+v.Details)
				}
				break
			}
		}
	}
	details = append(details, "", render.Style(fmt.Sprintf("Reasons (%d)", len(finding.Reasons)), render.Bold, render.Magenta), "")
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

func (m *ScanModel) buildSourceListModel() *listModel {
	items := m.sourceExplorerItems()
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(),
		controls:       []string{keyHint("/", "search") + " " + keyHint("Enter", "focus details") + " " + keyHint("→", "expand") + " " + keyHint("←", "collapse") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all"), render.Style("Mode: ", render.Dim) + render.Style("JSON tree", render.BgYellow, render.Bold) + render.Style(" | Nodes: ", render.Dim) + fmt.Sprintf("%d", sourceNodeCount(m))},
		listTitle:      fmt.Sprintf("Source (%d nodes)", sourceNodeCount(m)),
		detailTitle:    "-",
		navigationHelp: interactiveCommonNavigationHelp + "; → expands; Enter focuses details/collapses source nodes",
		filterHelp:     "Use / to search; Enter focuses details; Esc clears search; 1-7 switch tabs",
		emptyState:     "No source data is available.",
		items:          items,
	}
}

func (m *ScanModel) sourceExplorerItems() []listItem {
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
		{"subprojects", fmt.Sprintf("subprojects: [] (%d items)", len(m.subprojects)), false},
		{"manifests", fmt.Sprintf("manifests: [] (%d items)", len(m.manifests)), false},
		{"packages", fmt.Sprintf("packages: [] (%d items)", graphSize(m.graphValue)), false},
		{"relationships", fmt.Sprintf("relationships: [] (%d items)", relationshipCount(m.graphValue)), true},
	}
	for _, section := range sections {
		tree := "├─ "
		if section.last {
			tree = "└─ "
		}
		expanded := expandedValue(m.sourceExpanded, section.key, false)
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

func (m *ScanModel) sourceSectionChildren(section, prefix string) []listItem {
	switch section {
	case "target":
		lines := []string{
			fmt.Sprintf("name: %q", valueOrDash(m.project.Name)),
			fmt.Sprintf("path: %q", valueOrDash(m.project.Path)),
			fmt.Sprintf("type: %q", targetKindLabel(m.project)),
			fmt.Sprintf("ecosystem: %q", valueOrDash(string(m.project.Ecosystem))),
			fmt.Sprintf("packageManager: %q", valueOrDash(m.project.PackageManager.Name())),
		}
		return sourceLeafItems(lines, prefix)
	case "subprojects":
		out := make([]listItem, 0, len(m.subprojects))
		for idx, sub := range m.subprojects {
			last := idx == len(m.subprojects)-1
			tree := prefix + branch(last)
			out = append(out, sourceNode(fmt.Sprintf("%q: {ecosystem: %q, detector: %q}", sub.Subproject.RelativePath, string(sub.Subproject.Ecosystem), sub.Subproject.PrimaryDetector), "subproject:"+sub.Subproject.RelativePath, tree, 2, false, false))
		}
		return out
	case "manifests":
		out := make([]listItem, 0, len(m.manifests))
		for idx, manifest := range m.manifests {
			last := idx == len(m.manifests)-1
			tree := prefix + branch(last)
			attrs := fmt.Sprintf("subproject: %q, ecosystem: %q, components: %d", valueOrDefault(manifest.relativePath, "."), manifestEcosystem(m.graphValue, manifest), manifestComponentCount(m.graphValue, manifest.rootID))
			if moduleDir := manifestModuleDir(manifest); moduleDir != "" {
				attrs = fmt.Sprintf("subproject: %q, module: %q, ecosystem: %q, components: %d", valueOrDefault(manifest.relativePath, "."), moduleDir, manifestEcosystem(m.graphValue, manifest), manifestComponentCount(m.graphValue, manifest.rootID))
			}
			out = append(out, sourceNode(fmt.Sprintf("%q: {%s}", manifest.id, attrs), "manifest:"+manifest.id, tree, 2, false, false))
		}
		return out
	case "packages":
		var pkgs []*sdk.Dependency
		if m.graphValue != nil {
			pkgs = append(pkgs, m.graphValue.Nodes()...)
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
			out = append(out, sourceLeafItems(packageRawLines(pkg, m.registry), childPrefix)...)
		}
		return out
	case "relationships":
		edges := relationshipRawLines(m.graphValue)
		return sourceLeafItems(edges, prefix)
	default:
		return nil
	}
}

func packageRawLines(pkg *sdk.Dependency, registry *sdk.PackageRegistry) []string {
	if pkg == nil {
		return nil
	}
	var licenseValues []string
	for _, lic := range licensesForDependency(registry, pkg) {
		if id := strings.TrimSpace(lic.SPDXExpression); id != "" {
			licenseValues = append(licenseValues, id)
		} else if v := strings.TrimSpace(lic.Value); v != "" {
			licenseValues = append(licenseValues, v)
		}
	}
	lines := []string{
		fmt.Sprintf("name: %q", valueOrDash(pkg.Name)),
		fmt.Sprintf("version: %q", valueOrDash(pkg.Version)),
		fmt.Sprintf("ecosystem: %q", valueOrDash(string(pkg.Ecosystem))),
		fmt.Sprintf("scope: %q", valueOrDash(string(pkg.PrimaryScope()))),
		fmt.Sprintf("type: %q", valueOrDash(string(pkg.Type))),
		fmt.Sprintf("purl: %q", valueOrDash(pkg.PURL)),
		fmt.Sprintf("licenses: %q", strings.Join(licenseValues, ", ")),
		fmt.Sprintf("vulnerabilities: %d", len(vulnsForDependency(registry, pkg))),
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
	pkgs := graphValue.Nodes()
	sort.Slice(pkgs, func(i, j int) bool { return packageSortKey(pkgs[i]) < packageSortKey(pkgs[j]) })
	lines := make([]string, 0)
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		deps, err := graphValue.DirectDependencies(pkg.ID)
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

func sourceNodeCount(m *ScanModel) int {
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

func licenseRows(graphValue *sdk.Graph, registry *sdk.PackageRegistry) []licenseRow {
	if graphValue == nil {
		return nil
	}

	rowsByLicense := make(map[string]map[string]licensePackageRef)
	for _, pkg := range graphValue.Nodes() {
		if pkg == nil {
			continue
		}
		for _, lic := range licensesForDependency(registry, pkg) {
			licenseValue := strings.TrimSpace(lic.SPDXExpression)
			if licenseValue == "" {
				licenseValue = strings.TrimSpace(lic.Value)
			}
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
				scope:       string(pkg.PrimaryScope()),
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

func (m *ScanModel) buildComponentListModel(manifest listPackageRow) *listModel {
	if m.explainMode {
		return m.buildExplainComponentListModel(manifest)
	}
	rootPkg, _ := m.graphValue.Node(manifest.rootID)

	rows := m.componentTreeRows(manifest.rootID)
	// Compute highest severity per package for badge display, filtering, and sorting.
	maxSevByID := maxVulnerabilitySeverityByPkgID(m.graphValue, m.registry)
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
		deps, _ := m.graphValue.DirectDependencies(row.id)
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
			details:  componentDetails(m.graphValue, m.registry, row, manifest),
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
		summary:        m.scanSummaryLines(),
		controls:       []string{m.componentControlsLine() + render.Style(" | Manifest: ", render.Dim) + manifest.displayName + render.Style(" | Root: ", render.Dim) + packageDisplayName(rootPkg)},
		listTitle:      fmt.Sprintf("Components (%d)", len(rows)),
		detailTitle:    "Component Details",
		navigationHelp: navigationHelp,
		filterHelp:     "Use / to search; Enter focuses details; Esc clears search; r relationship; s scope; v severity; 1-7 tabs",
		emptyState:     "No components were found for this manifest.",
		items:          items,
	}
}

func (m *ScanModel) buildExplainComponentListModel(manifest listPackageRow) *listModel {
	labels, counts := explainRelationships(m.graphValue, manifest.targetID)
	rows := make([]listPackageRow, 0, len(labels))
	if m.graphValue != nil {
		for _, pkg := range m.graphValue.Nodes() {
			if pkg == nil {
				continue
			}
			row := packageRowFromGraph(pkg, labels[pkg.ID])
			row.targetID = manifest.targetID
			rows = append(rows, row)
		}
	}
	maxSevByID := maxVulnerabilitySeverityByPkgID(m.graphValue, m.registry)
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
			details:  componentDetails(m.graphValue, m.registry, row, manifest),
		})
	}
	targetPkg, _ := m.graphValue.Node(manifest.targetID)
	return &listModel{
		title:          fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary:        m.scanSummaryLines(),
		controls:       []string{m.componentControlsLine() + render.Style(" | Target: ", render.Dim) + packageDisplayName(targetPkg) + render.Style(" | Self/Parents/Ancestors/Roots: ", render.Dim) + fmt.Sprintf("%d/%d/%d/%d", counts["self"], counts["parent"], counts["ancestor"], counts["root"])},
		listTitle:      fmt.Sprintf("Components (%d)", len(rows)),
		detailTitle:    "Component Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter focuses details; Esc clears search; r relationship; s scope; v severity; 1-7 tabs",
		emptyState:     "No components were found for this explanation.",
		items:          items,
	}
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
	rootPkg, _ := graphValue.Node(row.rootID)
	lines := []string{
		render.Style("Manifest", render.Bold, render.Cyan),
		render.Style("  Name: ", render.Dim) + row.displayName,
		render.Style("  ID: ", render.Dim) + valueOrDash(row.id),
		render.Style("  Kind: ", render.Dim) + valueOrDash(filepath.Base(row.id)),
		render.Style("  Type: ", render.Dim) + statusText(row.relationship),
		render.Style("  Ecosystem: ", render.Dim) + valueOrDash(row.ecosystem),
		render.Style("  Package managers: ", render.Dim) + valueOrDash(row.packageManagers),
		render.Style("  Subproject: ", render.Dim) + valueOrDash(row.relativePath),
		render.Style("  Module dir: ", render.Dim) + valueOrDash(manifestModuleDir(row)),
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
	for _, pkg := range graphValue.Nodes() {
		if pkg == nil {
			continue
		}
		deps, err := graphValue.DirectDependencies(pkg.ID)
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

func packageRowFromGraph(pkg *sdk.Dependency, relationship string) listPackageRow {
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
		scope:        string(pkg.PrimaryScope()),
		ecosystem:    string(pkg.Ecosystem),
		relationship: relationship,
		purl:         pkg.PURL,
	}
}

func (m *ScanModel) componentTreeRows(rootID string) []listPackageRow {
	return m.componentTreeRowsFrom(rootID, true)
}

// componentSubtreeRows returns the component rows of rootID's children as a
// top-level forest: the root itself is absorbed by its merged project/module
// node, so it is neither emitted nor gated on its own expansion state.
func (m *ScanModel) componentSubtreeRows(rootID string) []listPackageRow {
	return m.componentTreeRowsFrom(rootID, false)
}

func (m *ScanModel) componentTreeRowsFrom(rootID string, includeRoot bool) []listPackageRow {
	if m == nil || m.graphValue == nil || strings.TrimSpace(rootID) == "" {
		return nil
	}
	rootPkg, ok := m.graphValue.Node(rootID)
	if !ok || rootPkg == nil {
		return nil
	}
	rows := make([]listPackageRow, 0)
	renderedSubtrees := make(map[string]struct{})
	var walk func(pkg *sdk.Dependency, depth int, ancestors []bool, last bool, visited map[string]struct{})
	walk = func(pkg *sdk.Dependency, depth int, ancestors []bool, last bool, visited map[string]struct{}) {
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
		if depth > 0 || includeRoot {
			rows = append(rows, row)
		}

		expanded := expandedValue(m.componentExpanded, pkg.ID, false)
		if depth == 0 && !includeRoot {
			// The absorbed root's children render whenever the merged node is
			// expanded; the root row itself no longer gates them.
			expanded = true
		}
		if !expanded {
			return
		}
		deps, err := m.graphValue.DirectDependencies(pkg.ID)
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
		children := make([]*sdk.Dependency, 0, len(deps))
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

func packageDisplayName(pkg *sdk.Dependency) string {
	if pkg == nil {
		return "-"
	}
	name := pkg.DisplayName()
	if pkg.Version != "" {
		name += "@" + pkg.Version
	}
	if string(pkg.PrimaryScope()) != "" {
		name += " [" + string(pkg.PrimaryScope()) + "]"
	}
	return name
}

func componentBaseName(value string) string {
	if idx := strings.LastIndex(value, " ["); idx >= 0 && strings.HasSuffix(value, "]") {
		return value[:idx]
	}
	return value
}

func componentDetails(graphValue *sdk.Graph, registry *sdk.PackageRegistry, row listPackageRow, manifest listPackageRow) []string {
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

	appendPackages := func(title string, packages []*sdk.Dependency) {
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
			if string(pkg.PrimaryScope()) != "" {
				value += " [" + string(pkg.PrimaryScope()) + "]"
			}
			lines = append(lines, render.Style("  - ", render.Dim)+value)
		}
		lines = append(lines, "")
	}

	if graphValue != nil {
		deps, _ := graphValue.DirectDependencies(row.id)
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
	var pkg *sdk.Dependency
	if graphValue != nil {
		pkg, _ = graphValue.Node(row.id)
	}
	vulnerabilities := vulnsForDependency(registry, pkg)
	lines = append(lines, render.Style(fmt.Sprintf("Vulnerabilities (%d)", len(vulnerabilities)), render.Bold, render.Cyan), "")
	if len(vulnerabilities) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, vulnerability := range vulnerabilities {
			var severityLabel string
			switch strings.ToLower(string(vulnerability.ParsedSeverity)) {
			case "critical":
				severityLabel = render.Style(" "+strings.ToUpper(valueOrDash(string(vulnerability.ParsedSeverity)))+" ", render.BgRed, render.White, render.Bold)
			case "high":
				severityLabel = render.Style(" "+strings.ToUpper(valueOrDash(string(vulnerability.ParsedSeverity)))+" ", render.BgRed, render.White)
			case "medium":
				severityLabel = render.Style(" "+strings.ToUpper(valueOrDash(string(vulnerability.ParsedSeverity)))+" ", render.BgYellow, render.Bold)
			case "low":
				severityLabel = render.Style(" "+strings.ToUpper(valueOrDash(string(vulnerability.ParsedSeverity)))+" ", render.BgCyan, render.Blue, render.Bold)
			default:
				severityLabel = render.Style(" "+strings.ToUpper(valueOrDash(string(vulnerability.ParsedSeverity)))+" ", render.Dim)
			}
			title := valueOrDash(vulnerability.Title)
			if title == "-" {
				title = ""
			} else {
				title = " " + title
			}
			lines = append(lines, "  "+severityLabel+" "+render.Style(vulnerability.ID, render.Bold)+title)
		}
	}
	lines = append(lines, "")

	// Licenses section
	licenses := licensesForDependency(registry, pkg)
	lines = append(lines, render.Style(fmt.Sprintf("Licenses (%d)", len(licenses)), render.Bold, render.Cyan), "")
	if len(licenses) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	} else {
		for _, lic := range licenses {
			expr := lic.SPDXExpression
			if expr == "" {
				expr = lic.Value
			}
			if lic.Type != "" {
				expr += " [" + string(lic.Type) + "]"
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

type packageVulnerabilityRow struct {
	pkg           *sdk.Dependency
	vulnerability sdk.Vulnerability
}

func packageVulnerabilityRows(graphValue *sdk.Graph, registry *sdk.PackageRegistry) []packageVulnerabilityRow {
	if graphValue == nil {
		return nil
	}
	rows := make([]packageVulnerabilityRow, 0)
	for _, pkg := range graphValue.Nodes() {
		if pkg == nil {
			continue
		}
		for _, vulnerability := range vulnsForDependency(registry, pkg) {
			rows = append(rows, packageVulnerabilityRow{pkg: pkg, vulnerability: vulnerability})
		}
	}
	return rows
}

func scanStats(graphValue *sdk.Graph, registry *sdk.PackageRegistry) scanOverviewStats {
	stats := scanOverviewStats{ecosystems: make(map[string]int)}
	licenseSet := make(map[string]struct{})
	if graphValue != nil {
		stats.components = graphValue.Size()
		for _, pkg := range graphValue.Nodes() {
			if pkg == nil {
				continue
			}
			if pkg.Ecosystem != "" {
				stats.ecosystems[string(pkg.Ecosystem)]++
			} else {
				stats.ecosystems["unknown"]++
			}
			for _, lic := range licensesForDependency(registry, pkg) {
				id := strings.TrimSpace(lic.SPDXExpression)
				if id == "" {
					id = strings.TrimSpace(lic.Value)
				}
				if id != "" {
					licenseSet[id] = struct{}{}
				}
			}
			stats.vulnerabilities += len(vulnsForDependency(registry, pkg))
		}
	}
	stats.licenses = len(licenseSet)
	return stats
}

func severityDistribution(vulnerabilities []packageVulnerabilityRow) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
	for _, row := range vulnerabilities {
		sev := strings.ToLower(strings.TrimSpace(string(row.vulnerability.ParsedSeverity)))
		if _, ok := counts[sev]; !ok {
			sev = "unknown"
		}
		counts[sev]++
	}
	return counts
}

func reachableSeverityDistribution(vulnerabilities []packageVulnerabilityRow) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
	for _, row := range vulnerabilities {
		if row.vulnerability.Reachability == nil || row.vulnerability.Reachability.Status != sdk.ReachabilityReachable {
			continue
		}
		severity := strings.ToLower(strings.TrimSpace(string(row.vulnerability.ParsedSeverity)))
		if _, ok := counts[severity]; !ok {
			severity = "unknown"
		}
		counts[severity]++
	}
	return counts
}

func severityDistributionDetails(title string, vulnerabilities []packageVulnerabilityRow, includeReachability bool) []string {
	counts := severityDistribution(vulnerabilities)
	reachableCounts := reachableSeverityDistribution(vulnerabilities)
	lines := []string{render.Style(title, render.Bold, render.Cyan)}
	for _, severity := range sortedCountKeys(counts) {
		value := fmt.Sprintf("%d", counts[severity])
		if includeReachability {
			value += fmt.Sprintf(" (%d reachable)", reachableCounts[severity])
		}
		lines = append(lines, render.Style("  "+severity+": ", render.Dim)+value+" "+barLine(counts[severity], maxCount(counts)))
	}
	if len(lines) == 1 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	}
	return lines
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

func summaryCountCardLines(count int, unit string, width int, color string, extra ...string) []string {
	lines := []string{
		centerLine(render.Style(fmt.Sprintf("%d", count), color, render.Bold), width),
		centerLine(render.Style(unit, render.Dim), width),
	}
	return append(lines, extra...)
}

func severityCardLine(vulnerabilities []packageVulnerabilityRow, severity string, includeReachability bool) string {
	counts := severityDistribution(vulnerabilities)
	reachableCounts := reachableSeverityDistribution(vulnerabilities)
	label := titleCase(severity)
	value := fmt.Sprintf("%d %s", counts[severity], label)
	if includeReachability {
		value += fmt.Sprintf(" (%d reachable)", reachableCounts[severity])
	}
	return severityColor(severity, value)
}

func severityDistributionLines(vulnerabilities []packageVulnerabilityRow, width int, includeReachability bool) []string {
	counts := severityDistribution(vulnerabilities)
	reachableCounts := reachableSeverityDistribution(vulnerabilities)
	total := 0
	for _, severity := range []string{"critical", "high", "medium", "low", "unknown"} {
		total += counts[severity]
	}
	maxVal := maxCount(counts)
	lines := make([]string, 0, 5)
	for _, severity := range []string{"critical", "high", "medium", "low", "unknown"} {
		label := titleCase(severity)
		if includeReachability {
			label += fmt.Sprintf(" (%d reachable)", reachableCounts[severity])
		}
		lines = append(lines, distributionLine(label, counts[severity], total, maxVal, severityColorCode(severity), width))
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
	maxVal := maxCount(counts)
	lines := make([]string, 0, len(keys))
	for idx, key := range keys {
		lines = append(lines, distributionLine(key, counts[key], total, maxVal, paletteColor(idx), width))
	}
	return lines
}

func distributionLine(label string, value, total, maxVal int, color string, width int) string {
	if width < 32 {
		width = 32
	}
	percent := 0
	if total > 0 {
		percent = value * 100 / total
	}
	text := fmt.Sprintf("%d %s (%d%%)", value, label, percent)
	// Scale the label column with the pane width so composite labels like
	// "1 changed runtime (100%)" don't get truncated mid-percentage.
	// Floor of 22 keeps short labels in narrow panes looking the same as
	// before; cap of 40 keeps the bar visible on very wide screens.
	//
	// Sizing contract: this function is called by panes that have already
	// budgeted `width` as the pane's inner width (caller passes
	// `paneWidth-2`). boxView then reserves another 2 cols for horizontal
	// padding, so the actual visible content area is `width-2`. Layout:
	//
	//   padRight(text, textWidth+2) + bar(barWidth)   ==>   total = width - 2
	//
	// Anything longer gets clipped by boxView and we lose the bar tail.
	textWidth := width / 2
	if textWidth < 22 {
		textWidth = 22
	}
	if textWidth > 40 {
		textWidth = 40
	}
	// Bar takes whatever's left after the label column. We prefer at
	// least 8 cols of bar, but never at the cost of overflowing the
	// `width-2` box budget — when the pane is genuinely narrow, the
	// label column shrinks rather than the bar overrun the borders.
	barWidth := width - textWidth - 4 // -2 for padRight gap, -2 for box horizontal padding
	if barWidth < 8 {
		barWidth = 8
		textWidth = width - barWidth - 4
		if textWidth < 8 {
			textWidth = 8
			barWidth = width - textWidth - 4
			if barWidth < 1 {
				barWidth = 1
			}
		}
	}
	return padRight(truncateToWidth(text, textWidth), textWidth+2) + coloredBarLine(value, maxVal, barWidth, color)
}

func coloredBarLine(value, maxVal, width int, color string) string {
	filled := 0
	if maxVal > 0 {
		filled = value * width / maxVal
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

func unknownLicenseCount(graphValue *sdk.Graph, registry *sdk.PackageRegistry) int {
	count := 0
	for _, row := range licenseRows(graphValue, registry) {
		if isUnknownLicense(row.license) {
			count += len(row.packages)
		}
	}
	return count
}

func unrecognizedLicenseCount(graphValue *sdk.Graph, registry *sdk.PackageRegistry) int {
	count := 0
	for _, row := range licenseRows(graphValue, registry) {
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

func groupedLicenseCounts(graphValue *sdk.Graph, registry *sdk.PackageRegistry, limit int) map[string]int {
	counts := make(map[string]int)
	for _, row := range licenseRows(graphValue, registry) {
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

func topVulnerableComponentStats(graphValue *sdk.Graph, registry *sdk.PackageRegistry, limit int) []componentStat {
	counts, severities := packageVulnerabilityStats(graphValue, registry)
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

func topDependedOnComponentStats(graphValue *sdk.Graph, registry *sdk.PackageRegistry, limit int) []componentStat {
	vulnCounts, _ := packageVulnerabilityStats(graphValue, registry)
	stats := make([]componentStat, 0)
	if graphValue != nil {
		for _, pkg := range graphValue.Nodes() {
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

func packageVulnerabilityStats(graphValue *sdk.Graph, registry *sdk.PackageRegistry) (map[string]int, map[string]string) {
	counts := make(map[string]int)
	severities := make(map[string]string)
	if graphValue != nil {
		for _, pkg := range graphValue.Nodes() {
			vulns := vulnsForDependency(registry, pkg)
			if pkg == nil || len(vulns) == 0 {
				continue
			}
			name := packageDisplayName(pkg)
			counts[name] += len(vulns)
			for _, vuln := range vulns {
				if severityRank(string(vuln.ParsedSeverity)) < severityRank(severities[name]) {
					severities[name] = string(vuln.ParsedSeverity)
				}
			}
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
			// Full relative path: base names collide across modules (three
			// pom.xml rows would be indistinguishable).
			padRight(truncateToWidth(manifest.id, nameWidth), nameWidth)+
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
			padRight(truncateToWidth(manifest.id, nameWidth), nameWidth)+
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

func vulnerableComponentTotal(graphValue *sdk.Graph, registry *sdk.PackageRegistry) int {
	counts, _ := packageVulnerabilityStats(graphValue, registry)
	return len(counts)
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

func licenseDistributionDetails(graphValue *sdk.Graph, registry *sdk.PackageRegistry) []string {
	counts := make(map[string]int)
	for _, row := range licenseRows(graphValue, registry) {
		counts[row.license] = len(row.packages)
	}
	return distributionDetails("License Distribution", counts)
}

func topVulnerableComponentDetails(graphValue *sdk.Graph, registry *sdk.PackageRegistry) []string {
	return distributionDetails("Top Vulnerable Components", topCounts(topVulnerableCounts(graphValue, registry), 10))
}

func topDependedOnDetails(graphValue *sdk.Graph) []string {
	return distributionDetails("Top Depended-On Components", topCounts(topDependedOnCounts(graphValue), 10))
}

func topVulnerableCounts(graphValue *sdk.Graph, registry *sdk.PackageRegistry) map[string]int {
	counts := make(map[string]int)
	if graphValue == nil {
		return counts
	}
	for _, pkg := range graphValue.Nodes() {
		vulns := vulnsForDependency(registry, pkg)
		if pkg == nil || len(vulns) == 0 {
			continue
		}
		counts[packageDisplayName(pkg)] += len(vulns)
	}
	return counts
}

func topDependedOnCounts(graphValue *sdk.Graph) map[string]int {
	counts := make(map[string]int)
	if graphValue == nil {
		return counts
	}
	for _, pkg := range graphValue.Nodes() {
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
	maxVal := 0
	for _, value := range counts {
		if value > maxVal {
			maxVal = value
		}
	}
	return maxVal
}

func barLine(value, maxVal int) string {
	width := 18
	filled := 0
	if maxVal > 0 {
		filled = value * width / maxVal
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

func graphSize(graphValue *sdk.Graph) int {
	if graphValue == nil {
		return 0
	}
	return graphValue.Size()
}

func relationshipCount(graphValue *sdk.Graph) int {
	count := 0
	if graphValue != nil {
		graphValue.WalkEdges(func(_, _ *sdk.Dependency) bool {
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
		return project.PackageManager.Name()
	case project.Ecosystem != "":
		return string(project.Ecosystem)
	default:
		return "dependency graph"
	}
}

func rootDependencies(graphValue *sdk.Graph, rootID string) rootDependencyGroup {
	if graphValue == nil || strings.TrimSpace(rootID) == "" {
		return rootDependencyGroup{}
	}

	direct, err := graphValue.DirectDependencies(rootID)
	if err != nil || len(direct) == 0 {
		return rootDependencyGroup{}
	}

	directByID := make(map[string]*sdk.Dependency, len(direct))
	for _, pkg := range direct {
		directByID[pkg.ID] = pkg
	}

	transitiveByID := make(map[string]*sdk.Dependency)
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
		dependencies, depErr := graphValue.DirectDependencies(currentID)
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

	transitive := make([]*sdk.Dependency, 0, len(transitiveByID))
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

func packageSortKey(pkg *sdk.Dependency) string {
	if pkg == nil {
		return ""
	}
	return pkg.ID + "\x00" + pkg.DisplayName() + "\x00" + pkg.Version
}
