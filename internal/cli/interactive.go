package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/output"
	"github.com/bomly/bomly-cli/internal/scan"
	"github.com/bomly/bomly-cli/internal/viewmodel"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

type interactiveModel interface {
	View(width, height int) string
	Move(delta int)
	Home()
	End()
}

type interactiveFilterModel interface {
	interactiveModel
	CycleRelationshipFilter()
	CycleScopeFilter()
	CycleSeverityFilter()
}

type interactiveTabbedModel interface {
	CycleView()
}

type interactiveSearchModel interface {
	interactiveModel
	BeginSearch()
	AppendSearch(value string)
	BackspaceSearch()
	CancelSearch()
	ConfirmSearch()
	IsSearching() bool
}

type interactiveNavigationModel interface {
	OpenSelected()
	GoBack()
	CanGoBack() bool
}

type interactiveDetailScrollModel interface {
	ScrollDetails(delta int)
}

type interactiveListItem struct {
	title    string
	subtitle string
	badges   []interactiveBadge
	details  []string
}

type interactiveBadge struct {
	label string
	kind  string
}

type interactiveListModel struct {
	title          string
	summary        []string
	navigationHelp string
	filterHelp     string
	emptyState     string
	items          []interactiveListItem
	selected       int
	scrollOffset   int
	detailOffset   int
	searching      bool
	searchQuery    string
	searchMatch    bool
}

const interactiveCommonNavigationHelp = "Up/Down or j/k move; PgUp/PgDn or Ctrl+u/Ctrl+d scroll details; Home/End or g/G jump; q quits"

type interactiveListPackageRow struct {
	id           string
	rootID       string
	targetID     string
	displayName  string
	version      string
	scope        string
	relationship string
	purl         string
}

type interactiveRootDependencyGroup struct {
	direct     []*model.Package
	transitive []*model.Package
}

type interactiveScanMode string

const (
	interactiveScanModeManifests  interactiveScanMode = "manifests"
	interactiveScanModeComponents interactiveScanMode = "components"
)

type interactiveScanView string

const (
	interactiveScanViewPackages interactiveScanView = "packages"
	interactiveScanViewVulns    interactiveScanView = "vulnerabilities"
	interactiveScanViewLicenses interactiveScanView = "licenses"
)

type interactiveScanModel struct {
	titlePrefix        string
	project            output.ProjectDescriptor
	graphValue         *model.Graph
	explainMode        bool
	manifests          []interactiveListPackageRow
	manifestByID       map[string]interactiveListPackageRow
	mode               interactiveScanMode
	activeView         interactiveScanView
	findings           []scan.Finding
	currentManifestID  string
	allowManifestExit  bool
	relationshipFilter string
	scopeFilter        string
	severityFilter     string
	list               *interactiveListModel
}

type interactiveTeaModel struct {
	inner       interactiveModel
	width       int
	height      int
	quitting    bool
	confirmQuit bool
}

func runInteractiveModel(stdin io.Reader, stderr io.Writer, model interactiveModel) error {
	inFile, err := terminalFile(stdin)
	if err != nil {
		return invalidInputf("--interactive requires a terminal stdin")
	}
	outFile, err := terminalFile(stderr)
	if err != nil {
		return invalidInputf("--interactive requires a terminal stderr")
	}

	stdinFD := int(inFile.Fd())
	stdoutFD := int(outFile.Fd())
	if !term.IsTerminal(stdinFD) {
		return invalidInputf("--interactive requires a terminal stdin")
	}
	if !term.IsTerminal(stdoutFD) {
		return invalidInputf("--interactive requires a terminal stderr")
	}

	program := tea.NewProgram(
		&interactiveTeaModel{inner: model, width: 100, height: 30},
		tea.WithInput(inFile),
		tea.WithOutput(outFile),
		tea.WithAltScreen(),
	)
	if _, err := program.Run(); err != nil {
		return fmt.Errorf("run interactive terminal mode: %w", err)
	}
	return nil
}

func terminalFile(value any) (*os.File, error) {
	file, ok := value.(*os.File)
	if !ok || file == nil {
		return nil, fmt.Errorf("not a terminal file")
	}
	return file, nil
}

func (m *interactiveTeaModel) Init() tea.Cmd {
	return nil
}

func (m *interactiveTeaModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if searchModel, ok := m.inner.(interactiveSearchModel); ok && searchModel.IsSearching() {
			switch msg.Type {
			case tea.KeyEsc:
				searchModel.CancelSearch()
			case tea.KeyEnter:
				searchModel.ConfirmSearch()
			case tea.KeyBackspace:
				searchModel.BackspaceSearch()
			default:
				if msg.String() == "backspace" {
					searchModel.BackspaceSearch()
				} else if msg.Type == tea.KeyRunes && len(msg.Runes) > 0 {
					searchModel.AppendSearch(string(msg.Runes))
				}
			}
			return m, nil
		}
		switch msg.String() {
		case "/":
			if searchModel, ok := m.inner.(interactiveSearchModel); ok {
				searchModel.BeginSearch()
			}
		case "r":
			if filterModel, ok := m.inner.(interactiveFilterModel); ok {
				filterModel.CycleRelationshipFilter()
			}
		case "s":
			if filterModel, ok := m.inner.(interactiveFilterModel); ok {
				filterModel.CycleScopeFilter()
			}
		case "v":
			if filterModel, ok := m.inner.(interactiveFilterModel); ok {
				filterModel.CycleSeverityFilter()
			}
		case "enter":
			if m.confirmQuit {
				m.quitting = true
				return m, tea.Quit
			}
			if navigationModel, ok := m.inner.(interactiveNavigationModel); ok {
				navigationModel.OpenSelected()
			}
		case "left", "h", "backspace":
			if m.confirmQuit {
				m.confirmQuit = false
				return m, nil
			}
			if navigationModel, ok := m.inner.(interactiveNavigationModel); ok && navigationModel.CanGoBack() {
				navigationModel.GoBack()
			}
		case "up", "k":
			m.inner.Move(-1)
		case "down", "j":
			m.inner.Move(1)
		case "pgup", "ctrl+u":
			if detailModel, ok := m.inner.(interactiveDetailScrollModel); ok {
				detailModel.ScrollDetails(-1)
			}
		case "pgdown", "ctrl+d":
			if detailModel, ok := m.inner.(interactiveDetailScrollModel); ok {
				detailModel.ScrollDetails(1)
			}
		case "home", "g":
			m.inner.Home()
		case "end", "G", "shift+g":
			m.inner.End()
		case "tab":
			if tabbedModel, ok := m.inner.(interactiveTabbedModel); ok {
				tabbedModel.CycleView()
			}
		case "esc", "q", "ctrl+c":
			if m.confirmQuit && msg.String() == "esc" {
				m.confirmQuit = false
				return m, nil
			}
			if m.confirmQuit {
				m.quitting = true
				return m, tea.Quit
			}
			m.confirmQuit = true
			return m, nil
		}
	}
	return m, nil
}

func (m *interactiveTeaModel) View() string {
	if m.quitting {
		return ""
	}
	width := m.width
	if width <= 0 {
		width = 100
	}
	height := m.height
	if height <= 0 {
		height = 30
	}
	view := m.inner.View(width, height)
	if !m.confirmQuit {
		return view
	}
	confirmation := ansiStyled(" Exit Bomly interactive mode? Enter confirms, Esc/Backspace cancels. ", ansiBgRed, ansiWhite, ansiBold)
	if view == "" {
		return truncateToWidth(confirmation, width)
	}
	lines := strings.Split(view, "\n")
	if len(lines) == 0 {
		return truncateToWidth(confirmation, width)
	}
	lines[len(lines)-1] = truncateToWidth(confirmation, width)
	return strings.Join(lines, "\n")
}

func (m *interactiveListModel) Move(delta int) {
	visible := m.visibleItemIndices()
	if len(visible) == 0 {
		m.selected = 0
		m.scrollOffset = 0
		return
	}

	currentVisibleIndex := m.selectedVisibleIndex(visible)
	currentVisibleIndex += delta
	if currentVisibleIndex < 0 {
		currentVisibleIndex = 0
	}
	if currentVisibleIndex >= len(visible) {
		currentVisibleIndex = len(visible) - 1
	}
	m.selected = visible[currentVisibleIndex]
	m.detailOffset = 0
}

func (m *interactiveListModel) Home() {
	visible := m.visibleItemIndices()
	if len(visible) == 0 {
		m.selected = 0
		m.scrollOffset = 0
		return
	}
	m.selected = visible[0]
	m.scrollOffset = 0
	m.detailOffset = 0
}

func (m *interactiveListModel) End() {
	visible := m.visibleItemIndices()
	if len(visible) == 0 {
		m.selected = 0
		m.scrollOffset = 0
		return
	}
	m.selected = visible[len(visible)-1]
	m.detailOffset = 0
}

func (m *interactiveListModel) ScrollDetails(delta int) {
	if delta == 0 {
		return
	}
	m.detailOffset += delta
	if m.detailOffset < 0 {
		m.detailOffset = 0
	}
}

func (m *interactiveListModel) BeginSearch() {
	m.searching = true
	m.searchQuery = ""
	m.searchMatch = true
	m.scrollOffset = 0
}

func (m *interactiveListModel) AppendSearch(value string) {
	if !m.searching {
		return
	}
	m.searchQuery += value
	m.jumpToSearchMatch()
}

func (m *interactiveListModel) BackspaceSearch() {
	if !m.searching {
		return
	}
	if m.searchQuery == "" {
		return
	}
	runes := []rune(m.searchQuery)
	m.searchQuery = string(runes[:len(runes)-1])
	m.jumpToSearchMatch()
}

func (m *interactiveListModel) CancelSearch() {
	m.searching = false
	m.searchQuery = ""
	m.searchMatch = true
	m.scrollOffset = 0
}

func (m *interactiveListModel) ConfirmSearch() {
	m.searching = false
	m.scrollOffset = 0
}

func (m *interactiveListModel) IsSearching() bool {
	return m.searching
}

func (m *interactiveListModel) View(width, height int) string {
	if width < 60 {
		width = 60
	}
	if height < 12 {
		height = 12
	}

	var lines []string
	lines = append(lines, truncateToWidth(ansiStyled(" "+m.title+" ", ansiBgBlue, ansiWhite, ansiBold), width))
	for _, summaryLine := range m.summary {
		lines = append(lines, truncateToWidth(summaryLine, width))
	}
	if m.searching {
		lines = append(lines, truncateToWidth(m.searchLine(width), width))
	}
	lines = append(lines, ansiStyled(strings.Repeat("=", width), ansiDim, ansiGray))
	helpLines := interactiveHelpLines(m.navigationHelp, m.filterHelp, width)
	if len(helpLines) == 0 {
		helpLines = []string{""}
	}

	bodyHeight := height - len(lines) - 2
	if bodyHeight < 4 {
		bodyHeight = 4
	}

	visible := m.visibleItemIndices()
	if len(visible) == 0 {
		lines = append(lines, truncateToWidth(ansiStyled(m.emptyState, ansiYellow, ansiBold), width))
		lines = append(lines, ansiStyled(strings.Repeat("=", width), ansiDim, ansiGray))
		for _, helpLine := range helpLines {
			lines = append(lines, truncateToWidth(ansiStyled(helpLine, ansiDim), width))
		}
		return strings.Join(lines, "\n")
	}

	listWidth := width / 2
	if listWidth < 28 {
		listWidth = 28
	}
	detailWidth := width - listWidth - 3
	if detailWidth < 20 {
		detailWidth = 20
		listWidth = width - detailWidth - 3
	}

	selectedIndex := visible[m.selectedVisibleIndex(visible)]
	listLines := m.visibleListLines(listWidth, bodyHeight, visible)
	detailLines := m.visibleDetailLines(m.items[selectedIndex].details, detailWidth, bodyHeight)
	if len(detailLines) < bodyHeight {
		detailLines = append(detailLines, make([]string, bodyHeight-len(detailLines))...)
	}

	for idx := 0; idx < bodyHeight; idx++ {
		left := ""
		if idx < len(listLines) {
			left = listLines[idx]
		}
		right := ""
		if idx < len(detailLines) {
			right = detailLines[idx]
		}
		lines = append(lines, padRight(left, listWidth)+" "+ansiStyled("|", ansiDim, ansiGray)+" "+padRight(right, detailWidth))
	}

	lines = append(lines, ansiStyled(strings.Repeat("=", width), ansiDim, ansiGray))
	for _, helpLine := range helpLines {
		lines = append(lines, truncateToWidth(ansiStyled(helpLine, ansiDim), width))
	}
	return strings.Join(lines, "\n")
}

func interactiveHelpLines(navigationHelp, filterHelp string, width int) []string {
	lines := make([]string, 0, 4)
	navigationHelp = strings.TrimSpace(navigationHelp)
	filterHelp = strings.TrimSpace(filterHelp)
	if navigationHelp != "" {
		lines = append(lines, wrapTextLines("Navigation: "+navigationHelp, width)...)
	}
	if filterHelp != "" {
		lines = append(lines, wrapTextLines("Filter/Search: "+filterHelp, width)...)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func (m *interactiveListModel) searchLine(width int) string {
	status := ansiStyled("type to filter and jump", ansiBlue, ansiBold)
	switch {
	case strings.TrimSpace(m.searchQuery) == "":
		status = ansiStyled("type to filter and jump", ansiBlue, ansiBold)
	case !m.searchMatch:
		status = ansiStyled("no matches", ansiRed, ansiBold)
	default:
		status = ansiStyled(fmt.Sprintf("%d match(es)", len(m.visibleItemIndices())), ansiBlue, ansiBold)
	}
	line := ansiStyled("Search ", ansiDim) +
		ansiStyled("/"+m.searchQuery, ansiWhite, ansiBold) +
		ansiStyled("  Enter: keep  Esc: clear  Backspace: edit  ", ansiDim) +
		status
	return truncateToWidth(line, width)
}

func (m *interactiveListModel) visibleListLines(width, height int, visible []int) []string {
	if height <= 0 {
		return nil
	}
	selectedVisibleIndex := m.selectedVisibleIndex(visible)
	if selectedVisibleIndex < m.scrollOffset {
		m.scrollOffset = selectedVisibleIndex
	}
	if selectedVisibleIndex >= m.scrollOffset+height {
		m.scrollOffset = selectedVisibleIndex - height + 1
	}
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}

	out := make([]string, 0, height)
	end := m.scrollOffset + height
	if end > len(visible) {
		end = len(visible)
	}
	for visibleIdx := m.scrollOffset; visibleIdx < end; visibleIdx++ {
		idx := visible[visibleIdx]
		prefix := ansiStyled("  ", ansiDim)
		title := ansiStyled(m.items[idx].title, ansiWhite)
		if idx == m.selected {
			prefix = ansiStyled("> ", ansiBgBlue, ansiWhite, ansiBold)
			title = ansiStyled(m.items[idx].title, ansiWhite, ansiBold)
		}
		line := prefix + title
		if m.items[idx].subtitle != "" {
			line += " " + interactiveStatusBadge(m.items[idx].subtitle)
		}
		for _, badge := range m.items[idx].badges {
			line += " " + interactiveBadgeView(badge)
		}
		out = append(out, truncateToWidth(line, width))
	}
	for len(out) < height {
		out = append(out, "")
	}
	return out
}

func (m *interactiveListModel) visibleDetailLines(lines []string, width, height int) []string {
	if height <= 0 {
		return nil
	}
	wrapped := wrapLines(lines, width)
	maxOffset := len(wrapped) - height
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.detailOffset > maxOffset {
		m.detailOffset = maxOffset
	}
	if m.detailOffset < 0 {
		m.detailOffset = 0
	}
	start := m.detailOffset
	end := start + height
	if end > len(wrapped) {
		end = len(wrapped)
	}
	out := make([]string, 0, height)
	if start < end {
		out = append(out, wrapped[start:end]...)
	}
	return out
}

func (m *interactiveListModel) jumpToSearchMatch() {
	visible := m.visibleItemIndices()
	if len(m.items) == 0 {
		m.searchMatch = false
		return
	}
	query := strings.TrimSpace(strings.ToLower(m.searchQuery))
	if query == "" {
		m.searchMatch = true
		if len(visible) > 0 && (m.selected < 0 || m.selected >= len(m.items)) {
			m.selected = visible[0]
		}
		m.detailOffset = 0
		return
	}
	if len(visible) > 0 {
		m.selected = visible[0]
		m.scrollOffset = 0
		m.detailOffset = 0
		m.searchMatch = true
		return
	}
	m.searchMatch = false
}

func (m *interactiveListModel) visibleItemIndices() []int {
	query := strings.TrimSpace(strings.ToLower(m.searchQuery))
	if query == "" {
		indices := make([]int, len(m.items))
		for idx := range m.items {
			indices[idx] = idx
		}
		return indices
	}

	indices := make([]int, 0, len(m.items))
	for idx, item := range m.items {
		if interactiveItemMatches(item, query) {
			indices = append(indices, idx)
		}
	}
	return indices
}

func (m *interactiveListModel) selectedVisibleIndex(visible []int) int {
	if len(visible) == 0 {
		return 0
	}
	for idx, itemIndex := range visible {
		if itemIndex == m.selected {
			return idx
		}
	}
	m.selected = visible[0]
	return 0
}

func interactiveItemMatches(item interactiveListItem, query string) bool {
	if strings.Contains(strings.ToLower(item.title), query) {
		return true
	}
	if strings.Contains(strings.ToLower(item.subtitle), query) {
		return true
	}
	for _, badge := range item.badges {
		if strings.Contains(strings.ToLower(badge.label), query) {
			return true
		}
	}
	return false
}

func newScanInteractiveModel(project output.ProjectDescriptor, consolidated scan.ConsolidatedGraph, graphValue *model.Graph, findings []scan.Finding) *interactiveScanModel {
	return newScanNavigatorModel("Bomly Interactive Scan", project, consolidated, graphValue, findings)
}

func newScanNavigatorModel(titlePrefix string, project output.ProjectDescriptor, consolidated scan.ConsolidatedGraph, graphValue *model.Graph, findings []scan.Finding) *interactiveScanModel {
	manifests := interactiveManifestRows(consolidated)
	manifestByID := make(map[string]interactiveListPackageRow, len(manifests))
	for _, manifest := range manifests {
		manifestByID[manifest.id] = manifest
	}

	model := &interactiveScanModel{
		titlePrefix:       titlePrefix,
		project:           project,
		graphValue:        graphValue,
		explainMode:       strings.Contains(strings.ToLower(titlePrefix), "explain"),
		manifests:         manifests,
		manifestByID:      manifestByID,
		mode:              interactiveScanModeManifests,
		allowManifestExit: len(manifests) > 1,
		findings:          findings,
		activeView:        interactiveScanViewPackages,
	}
	if len(manifests) == 1 {
		model.mode = interactiveScanModeComponents
		model.currentManifestID = manifests[0].id
	}
	model.list = model.buildCurrentListModel()
	return model
}

func (m *interactiveScanModel) View(width, height int) string {
	if m == nil || m.list == nil {
		return ""
	}
	return m.list.View(width, height)
}

func (m *interactiveScanModel) Move(delta int) {
	if m == nil || m.list == nil {
		return
	}
	m.list.Move(delta)
}

func (m *interactiveScanModel) ScrollDetails(delta int) {
	if m == nil || m.list == nil {
		return
	}
	m.list.ScrollDetails(delta)
}

func (m *interactiveScanModel) Home() {
	if m == nil || m.list == nil {
		return
	}
	m.list.Home()
}

func (m *interactiveScanModel) End() {
	if m == nil || m.list == nil {
		return
	}
	m.list.End()
}

func (m *interactiveScanModel) BeginSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.BeginSearch()
}

func (m *interactiveScanModel) AppendSearch(value string) {
	if m == nil || m.list == nil {
		return
	}
	m.list.AppendSearch(value)
}

func (m *interactiveScanModel) BackspaceSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.BackspaceSearch()
}

func (m *interactiveScanModel) CancelSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.CancelSearch()
}

func (m *interactiveScanModel) ConfirmSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.ConfirmSearch()
}

func (m *interactiveScanModel) IsSearching() bool {
	if m == nil || m.list == nil {
		return false
	}
	return m.list.IsSearching()
}

func (m *interactiveScanModel) CycleView() {
	if m == nil {
		return
	}
	switch m.activeView {
	case interactiveScanViewPackages:
		m.activeView = interactiveScanViewVulns
	case interactiveScanViewVulns:
		m.activeView = interactiveScanViewLicenses
	default:
		m.activeView = interactiveScanViewPackages
	}
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) CycleRelationshipFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages || m.mode != interactiveScanModeComponents {
		return
	}
	m.relationshipFilter = nextInteractiveRelationshipFilter(m.relationshipFilter, m.explainMode)
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) CycleScopeFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages || m.mode != interactiveScanModeComponents {
		return
	}
	m.scopeFilter = nextInteractiveScopeFilter(m.scopeFilter)
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) CycleSeverityFilter() {
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
	m.severityFilter = nextInteractiveSeverityFilter(m.severityFilter)
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) OpenSelected() {
	if m == nil || m.list == nil || m.activeView != interactiveScanViewPackages || m.mode != interactiveScanModeManifests {
		return
	}
	visible := m.list.visibleItemIndices()
	if len(visible) == 0 {
		return
	}
	item := m.list.items[visible[m.list.selectedVisibleIndex(visible)]]
	manifestID := interactiveManifestIDFromTitle(item.title)
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

func (m *interactiveScanModel) GoBack() {
	if !m.CanGoBack() {
		return
	}
	m.mode = interactiveScanModeManifests
	m.currentManifestID = ""
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) CanGoBack() bool {
	if m == nil {
		return false
	}
	return m.activeView == interactiveScanViewPackages && m.mode == interactiveScanModeComponents && m.allowManifestExit
}

func (m *interactiveScanModel) buildCurrentListModel() *interactiveListModel {
	switch m.activeView {
	case interactiveScanViewVulns:
		return m.buildVulnsListModel()
	case interactiveScanViewLicenses:
		return m.buildLicensesListModel()
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

func (m *interactiveScanModel) buildManifestListModel() *interactiveListModel {
	items := make([]interactiveListItem, 0, len(m.manifests))
	for _, manifest := range m.manifests {
		title := manifest.displayName + " [" + manifest.id + "]"
		items = append(items, interactiveListItem{
			title:    title,
			subtitle: "manifest",
			details:  interactiveManifestDetails(m.graphValue, manifest),
		})
	}

	packageCount := 0
	if m.graphValue != nil {
		packageCount = m.graphValue.Size()
	}

	return &interactiveListModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: []string{
			ansiStyled("Tab: [PACKAGES] | Vulnerabilities | Licenses", ansiDim),
			ansiStyled(fmt.Sprintf("Manifests %d", len(m.manifests)), ansiCyan, ansiBold),
			ansiStyled(fmt.Sprintf("Packages  %d", packageCount), ansiCyan, ansiBold),
			ansiStyled("Project   ", ansiDim) + m.project.Path,
			ansiStyled("Ecosystem ", ansiDim) + valueOrDash(m.project.Ecosystem),
		},
		navigationHelp: interactiveCommonNavigationHelp + "; Enter opens selected manifest",
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search",
		emptyState:     "No manifests were found in the dependency graph.",
		items:          items,
	}
}

func (m *interactiveScanModel) buildVulnsListModel() *interactiveListModel {
	all := make([]scan.Finding, 0, len(m.findings))
	for _, f := range m.findings {
		if f.Kind == scan.FindingKindVulnerability {
			all = append(all, f)
		}
	}

	// Apply severity filter.
	filtered := all
	if m.severityFilter != "" {
		filtered = make([]scan.Finding, 0, len(all))
		for _, f := range all {
			if strings.EqualFold(f.Severity, m.severityFilter) {
				filtered = append(filtered, f)
			}
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		ri, rj := interactiveSeverityRank(filtered[i].Severity), interactiveSeverityRank(filtered[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return filtered[i].ID < filtered[j].ID
	})

	items := make([]interactiveListItem, 0, len(filtered))
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
		items = append(items, interactiveListItem{
			title:  titleStr,
			badges: []interactiveBadge{{label: f.Severity, kind: "severity-" + strings.ToLower(f.Severity)}},
			details: []string{
				ansiStyled("ID        ", ansiDim) + valueOrDash(f.ID),
				ansiStyled("Severity  ", ansiDim) + interactiveSeverityText(f.Severity),
				ansiStyled("Package   ", ansiDim) + valueOrDash(pkgName),
				ansiStyled("Title     ", ansiDim) + valueOrDash(f.Title),
				ansiStyled("Source    ", ansiDim) + valueOrDash(f.Source),
			},
		})
	}

	return &interactiveListModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: []string{
			ansiStyled("Tab: Packages | [VULNERABILITIES] | Licenses", ansiDim),
			ansiStyled("Filter severity ", ansiDim) + valueOrDash(m.severityFilter),
			ansiStyled(fmt.Sprintf("Showing %d / %d", len(filtered), len(all)), ansiCyan, ansiBold),
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; v cycles severity filter",
		emptyState:     "No vulnerabilities found. Run with --audit to enable vulnerability scanning.",
		items:          items,
	}
}

func (m *interactiveScanModel) buildLicensesListModel() *interactiveListModel {
	rows := interactiveLicenseRows(m.graphValue)
	items := make([]interactiveListItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, interactiveListItem{
			title:    row.license,
			subtitle: fmt.Sprintf("%d package(s)", len(row.packages)),
			details:  interactiveLicenseDetails(row),
		})
	}

	return &interactiveListModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: []string{
			ansiStyled("Tab: Packages | Vulnerabilities | [LICENSES]", ansiDim),
			ansiStyled(fmt.Sprintf("Unique licenses %d", len(rows)), ansiCyan, ansiBold),
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search",
		emptyState:     "No license information found.",
		items:          items,
	}
}

type interactiveLicenseRow struct {
	license  string
	packages []interactiveLicensePackageRef
}

type interactiveLicensePackageRef struct {
	id          string
	displayName string
	version     string
	scope       string
}

func interactiveLicenseRows(graphValue *model.Graph) []interactiveLicenseRow {
	if graphValue == nil {
		return nil
	}

	rowsByLicense := make(map[string]map[string]interactiveLicensePackageRef)
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
				packageRefs = make(map[string]interactiveLicensePackageRef)
				rowsByLicense[licenseValue] = packageRefs
			}
			packageRefs[pkg.ID] = interactiveLicensePackageRef{
				id:          pkg.ID,
				displayName: pkg.DisplayName(),
				version:     pkg.Version,
				scope:       pkg.Scope,
			}
		}
	}

	rows := make([]interactiveLicenseRow, 0, len(rowsByLicense))
	for licenseValue, packageRefs := range rowsByLicense {
		packages := make([]interactiveLicensePackageRef, 0, len(packageRefs))
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
		rows = append(rows, interactiveLicenseRow{
			license:  licenseValue,
			packages: packages,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].license < rows[j].license
	})
	return rows
}

func interactiveLicenseDetails(row interactiveLicenseRow) []string {
	lines := []string{
		ansiStyled("License", ansiBold, ansiCyan),
		ansiStyled("  Identifier: ", ansiDim) + valueOrDash(row.license),
		ansiStyled("  Package count: ", ansiDim) + fmt.Sprintf("%d", len(row.packages)),
		"",
		ansiStyled("Packages Using This License", ansiBold, ansiMagenta),
	}
	if len(row.packages) == 0 {
		lines = append(lines, ansiStyled("  (none)", ansiDim))
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
		lines = append(lines, ansiStyled("  - ", ansiDim)+label)
	}
	return lines
}

func (m *interactiveScanModel) buildComponentListModel(manifest interactiveListPackageRow) *interactiveListModel {
	if m.explainMode {
		return m.buildExplainComponentListModel(manifest)
	}
	rootPkg, _ := m.graphValue.Package(manifest.rootID)
	groups := interactiveRootDependencies(m.graphValue, manifest.rootID)

	// Build rows: root first, then direct, then transitive
	rows := make([]interactiveListPackageRow, 0, 1+len(groups.direct)+len(groups.transitive))

	// Add root package first
	if rootPkg != nil {
		rows = append(rows, interactivePackageRowFromGraph(rootPkg, "root"))
	}

	for _, pkg := range groups.direct {
		rows = append(rows, interactivePackageRowFromGraph(pkg, "direct"))
	}
	for _, pkg := range groups.transitive {
		rows = append(rows, interactivePackageRowFromGraph(pkg, "transitive"))
	}
	rows = filterInteractivePackageRows(rows, m.relationshipFilter, m.scopeFilter)

	// Compute highest severity per package for badge display, filtering, and sorting.
	maxSevByID := interactiveMaxSeverityByPkgID(m.findings)

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
		si := interactiveSeverityRank(maxSevByID[rows[i].id])
		sj := interactiveSeverityRank(maxSevByID[rows[j].id])
		if si != sj {
			return si < sj
		}
		if rows[i].relationship != rows[j].relationship {
			return interactiveRelationshipOrder(rows[i].relationship) < interactiveRelationshipOrder(rows[j].relationship)
		}
		return rows[i].id < rows[j].id
	})

	items := make([]interactiveListItem, 0, len(rows))
	for _, row := range rows {
		badges := interactivePackageBadges(row)
		if sev := maxSevByID[row.id]; sev != "" {
			// Prepend the severity badge so it appears before the scope badge.
			badges = append([]interactiveBadge{{label: sev, kind: "severity-" + strings.ToLower(sev)}}, badges...)
		}
		items = append(items, interactiveListItem{
			title:    row.displayName,
			subtitle: row.relationship,
			badges:   badges,
			details:  interactiveComponentDetails(m.graphValue, row, manifest, m.findings),
		})
	}

	navigationHelp := interactiveCommonNavigationHelp
	if m.allowManifestExit {
		navigationHelp += "; Backspace/Left/h returns to manifests"
	}

	return &interactiveListModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: []string{
			ansiStyled("Tab: [PACKAGES] | Vulnerabilities | Licenses", ansiDim),
			ansiStyled("Manifest  ", ansiDim) + manifest.displayName,
			ansiStyled("Root      ", ansiDim) + interactivePackageDisplayName(rootPkg),
			ansiStyled("Filter relationship ", ansiDim) + valueOrDash(m.relationshipFilter),
			ansiStyled("Filter scope ", ansiDim) + valueOrDash(m.scopeFilter),
			ansiStyled("Filter severity ", ansiDim) + valueOrDash(m.severityFilter),
			ansiStyled(fmt.Sprintf("Direct    %d", len(groups.direct)), ansiCyan, ansiBold),
			ansiStyled(fmt.Sprintf("Transitive %d", len(groups.transitive)), ansiCyan, ansiBold),
			ansiStyled("Project   ", ansiDim) + m.project.Path,
		},
		navigationHelp: navigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; r cycles relationship filter; s cycles scope filter; v cycles severity filter",
		emptyState:     "No components were found for this manifest.",
		items:          items,
	}
}

func (m *interactiveScanModel) buildExplainComponentListModel(manifest interactiveListPackageRow) *interactiveListModel {
	labels, counts := interactiveExplainRelationships(m.graphValue, manifest.targetID)
	rows := make([]interactiveListPackageRow, 0, len(labels))
	if m.graphValue != nil {
		for _, pkg := range m.graphValue.Packages() {
			if pkg == nil {
				continue
			}
			row := interactivePackageRowFromGraph(pkg, labels[pkg.ID])
			row.targetID = manifest.targetID
			rows = append(rows, row)
		}
	}
	rows = filterInteractivePackageRows(rows, m.relationshipFilter, m.scopeFilter)
	maxSevByID := interactiveMaxSeverityByPkgID(m.findings)
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
		si := interactiveSeverityRank(maxSevByID[rows[i].id])
		sj := interactiveSeverityRank(maxSevByID[rows[j].id])
		if si != sj {
			return si < sj
		}
		if rows[i].relationship != rows[j].relationship {
			return interactiveRelationshipOrder(rows[i].relationship) < interactiveRelationshipOrder(rows[j].relationship)
		}
		return rows[i].id < rows[j].id
	})
	items := make([]interactiveListItem, 0, len(rows))
	for _, row := range rows {
		badges := interactivePackageBadges(row)
		if sev := maxSevByID[row.id]; sev != "" {
			badges = append([]interactiveBadge{{label: sev, kind: "severity-" + strings.ToLower(sev)}}, badges...)
		}
		items = append(items, interactiveListItem{
			title:    row.displayName,
			subtitle: row.relationship,
			badges:   badges,
			details:  interactiveComponentDetails(m.graphValue, row, manifest, m.findings),
		})
	}
	targetPkg, _ := m.graphValue.Package(manifest.targetID)
	return &interactiveListModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: []string{
			ansiStyled("Tab: [PACKAGES] | Vulnerabilities | Licenses", ansiDim),
			ansiStyled("Manifest  ", ansiDim) + manifest.displayName,
			ansiStyled("Target    ", ansiDim) + interactivePackageDisplayName(targetPkg),
			ansiStyled("Filter relationship ", ansiDim) + valueOrDash(m.relationshipFilter),
			ansiStyled("Filter scope ", ansiDim) + valueOrDash(m.scopeFilter),
			ansiStyled("Filter severity ", ansiDim) + valueOrDash(m.severityFilter),
			ansiStyled(fmt.Sprintf("Self      %d", counts["self"]), ansiCyan, ansiBold),
			ansiStyled(fmt.Sprintf("Parents   %d", counts["parent"]), ansiCyan, ansiBold),
			ansiStyled(fmt.Sprintf("Ancestors %d", counts["ancestor"]), ansiCyan, ansiBold),
			ansiStyled(fmt.Sprintf("Roots     %d", counts["root"]), ansiCyan, ansiBold),
			ansiStyled("Project   ", ansiDim) + m.project.Path,
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; r cycles relationship filter; s cycles scope filter; v cycles severity filter",
		emptyState:     "No components were found for this explanation.",
		items:          items,
	}
}

func interactiveManifestIDFromTitle(value string) string {
	start := strings.LastIndex(value, "[")
	end := strings.LastIndex(value, "]")
	if start == -1 || end == -1 || end <= start+1 {
		return ""
	}
	return strings.TrimSpace(value[start+1 : end])
}

func interactiveManifestRows(consolidated scan.ConsolidatedGraph) []interactiveListPackageRow {
	if len(consolidated.Manifests) == 0 {
		return nil
	}

	rows := make([]interactiveListPackageRow, 0, len(consolidated.Manifests))
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

		rows = append(rows, interactiveListPackageRow{
			id:           manifestID,
			rootID:       rootID,
			targetID:     interactiveManifestTargetID(manifest.Entry.Graph),
			displayName:  manifestName,
			relationship: "manifest",
		})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	return rows
}

func interactiveManifestDetails(graphValue *model.Graph, row interactiveListPackageRow) []string {
	groups := interactiveRootDependencies(graphValue, row.rootID)
	rootPkg, _ := graphValue.Package(row.rootID)
	lines := []string{
		ansiStyled("Manifest", ansiBold, ansiCyan),
		ansiStyled("  Name: ", ansiDim) + row.displayName,
		ansiStyled("  ID: ", ansiDim) + valueOrDash(row.id),
		ansiStyled("  Kind: ", ansiDim) + valueOrDash(filepath.Base(row.id)),
		ansiStyled("  Type: ", ansiDim) + interactiveStatusText(row.relationship),
		"",
		ansiStyled("Dependencies", ansiBold, ansiMagenta),
		ansiStyled("  Root (project package): ", ansiDim) + interactivePackageDisplayName(rootPkg),
		ansiStyled("  Direct dependencies: ", ansiDim) + fmt.Sprintf("%d", len(groups.direct)),
		ansiStyled("  Transitive dependencies: ", ansiDim) + fmt.Sprintf("%d", len(groups.transitive)),
		"",
		ansiStyled("Press Enter to view components for this manifest.", ansiDim),
		"",
	}
	return lines
}

func interactiveManifestTargetID(graphValue *model.Graph) string {
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

func interactivePackageRowFromGraph(pkg *model.Package, relationship string) interactiveListPackageRow {
	if pkg == nil {
		return interactiveListPackageRow{relationship: relationship}
	}
	name := pkg.DisplayName()
	displayName := name
	if pkg.Version != "" {
		displayName = name + "@" + pkg.Version
	}
	return interactiveListPackageRow{
		id:           pkg.ID,
		rootID:       pkg.ID,
		displayName:  displayName,
		version:      pkg.Version,
		scope:        pkg.Scope,
		relationship: relationship,
		purl:         pkg.PURL,
	}
}

func interactivePackageDisplayName(pkg *model.Package) string {
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

func interactiveComponentBaseName(value string) string {
	if idx := strings.LastIndex(value, " ["); idx >= 0 && strings.HasSuffix(value, "]") {
		return value[:idx]
	}
	return value
}

func interactiveComponentDetails(graphValue *model.Graph, row interactiveListPackageRow, manifest interactiveListPackageRow, findings []scan.Finding) []string {
	lines := []string{
		ansiStyled("Component", ansiBold, ansiCyan),
		ansiStyled("  Manifest: ", ansiDim) + manifest.displayName,
		ansiStyled("  Name: ", ansiDim) + interactiveComponentBaseName(row.displayName),
		ansiStyled("  ID: ", ansiDim) + valueOrDash(row.id),
		ansiStyled("  Version: ", ansiDim) + valueOrDash(row.version),
		ansiStyled("  Scope: ", ansiDim) + valueOrDash(row.scope),
		ansiStyled("  Relationship: ", ansiDim) + interactiveStatusText(row.relationship),
		ansiStyled("  PURL: ", ansiDim) + valueOrDash(row.purl),
		"",
	}

	appendPackages := func(title string, packages []*model.Package) {
		lines = append(lines, ansiStyled(title, ansiBold, ansiMagenta))
		if len(packages) == 0 {
			lines = append(lines, ansiStyled("  (none)", ansiDim))
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
			lines = append(lines, ansiStyled("  - ", ansiDim)+value)
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
	lines = append(lines, ansiStyled("Vulnerabilities", ansiBold, ansiCyan))
	var pkgFindings []scan.Finding
	for _, f := range findings {
		if f.Kind == scan.FindingKindVulnerability && f.Package != nil && f.Package.ID == row.id {
			pkgFindings = append(pkgFindings, f)
		}
	}
	if len(pkgFindings) == 0 {
		lines = append(lines, ansiStyled("  (none)", ansiDim))
	} else {
		for _, f := range pkgFindings {
			var severityLabel string
			switch strings.ToLower(f.Severity) {
			case "critical":
				severityLabel = ansiStyled(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", ansiBgRed, ansiWhite, ansiBold)
			case "high":
				severityLabel = ansiStyled(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", ansiBgRed, ansiWhite)
			case "medium":
				severityLabel = ansiStyled(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", ansiBgYellow, ansiBold)
			case "low":
				severityLabel = ansiStyled(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", ansiBgCyan, ansiBlue, ansiBold)
			default:
				severityLabel = ansiStyled(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", ansiDim)
			}
			title := valueOrDash(f.Title)
			if title == "-" {
				title = ""
			} else {
				title = " " + title
			}
			lines = append(lines, "  "+severityLabel+" "+ansiStyled(f.ID, ansiBold)+title)
		}
	}
	lines = append(lines, "")

	// Licenses section
	lines = append(lines, ansiStyled("Licenses", ansiBold, ansiCyan))
	var pkg *model.Package
	if graphValue != nil {
		pkg, _ = graphValue.Package(row.id)
	}
	if pkg == nil || len(pkg.Licenses) == 0 {
		lines = append(lines, ansiStyled("  (none)", ansiDim))
	} else {
		for _, lic := range pkg.Licenses {
			expr := lic.SPDXExpression
			if expr == "" {
				expr = lic.Value
			}
			if lic.Type != "" {
				expr += " [" + lic.Type + "]"
			}
			lines = append(lines, ansiStyled("  - ", ansiDim)+valueOrDash(expr))
		}
	}
	lines = append(lines, "")

	return lines
}

func interactiveRootDependencies(graphValue *model.Graph, rootID string) interactiveRootDependencyGroup {
	if graphValue == nil || strings.TrimSpace(rootID) == "" {
		return interactiveRootDependencyGroup{}
	}

	direct, err := graphValue.Dependencies(rootID)
	if err != nil || len(direct) == 0 {
		return interactiveRootDependencyGroup{}
	}

	directByID := make(map[string]*model.Package, len(direct))
	for _, pkg := range direct {
		directByID[pkg.ID] = pkg
	}

	transitiveByID := make(map[string]*model.Package)
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

	transitive := make([]*model.Package, 0, len(transitiveByID))
	for _, pkg := range transitiveByID {
		transitive = append(transitive, pkg)
	}
	sort.Slice(direct, func(i, j int) bool {
		return interactivePackageSortKey(direct[i]) < interactivePackageSortKey(direct[j])
	})
	sort.Slice(transitive, func(i, j int) bool {
		return interactivePackageSortKey(transitive[i]) < interactivePackageSortKey(transitive[j])
	})

	return interactiveRootDependencyGroup{direct: direct, transitive: transitive}
}

func interactivePackageSortKey(pkg *model.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.ID + "\x00" + pkg.DisplayName() + "\x00" + pkg.Version
}

func newDiffInteractiveModel(payload viewmodel.DiffResponse) *interactiveListModel {
	manifests := append([]viewmodel.DiffManifestResult(nil), payload.Results.Manifests...)
	sort.Slice(manifests, func(i, j int) bool {
		left := manifests[i]
		right := manifests[j]
		if left.Status != right.Status {
			return diffManifestStatusOrder(left.Status) < diffManifestStatusOrder(right.Status)
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.PackageManager != right.PackageManager {
			return left.PackageManager < right.PackageManager
		}
		return left.Subproject < right.Subproject
	})

	items := make([]interactiveListItem, 0, len(manifests))
	for _, manifest := range manifests {
		items = append(items, interactiveListItem{
			title:    diffManifestDisplayLabel(manifest),
			subtitle: manifest.Status,
			details:  interactiveDiffManifestDetails(manifest),
		})
	}

	return &interactiveListModel{
		title: fmt.Sprintf("Bomly Interactive Diff: %s -> %s", payload.Comparison.Base, payload.Comparison.Head),
		summary: []string{
			interactiveSummaryLine("Manifest changes", []string{
				ansiStyled(fmt.Sprintf("added %d", payload.Summary.AddedManifestCount), ansiGreen, ansiBold),
				ansiStyled(fmt.Sprintf("changed %d", payload.Summary.ChangedManifestCount), ansiYellow, ansiBold),
				ansiStyled(fmt.Sprintf("unchanged %d", payload.Summary.UnchangedManifestCount), ansiCyan, ansiBold),
				ansiStyled(fmt.Sprintf("removed %d", payload.Summary.RemovedManifestCount), ansiRed, ansiBold),
			}),
			interactiveSummaryLine("Package changes", []string{
				ansiStyled(fmt.Sprintf("added %d", payload.Summary.AddedPackageCount), ansiGreen, ansiBold),
				ansiStyled(fmt.Sprintf("updated %d", payload.Summary.ChangedPackageCount), ansiYellow, ansiBold),
				ansiStyled(fmt.Sprintf("removed %d", payload.Summary.RemovedPackageCount), ansiRed, ansiBold),
			}),
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps current result; Esc clears search",
		emptyState:     "No manifest changes were found.",
		items:          items,
	}
}

func interactiveRelationshipOrder(relationship string) int {
	switch strings.ToLower(strings.TrimSpace(relationship)) {
	case "manifest":
		return 0
	case "self":
		return 1
	case "parent":
		return 2
	case "ancestor":
		return 3
	case "root":
		return 4
	case "direct":
		return 5
	case "transitive":
		return 6
	default:
		return 99
	}
}

func interactiveSummaryLine(label string, values []string) string {
	return ansiStyled(label+": ", ansiDim) + strings.Join(values, ansiStyled("  |  ", ansiDim))
}

func interactiveDiffManifestDetails(manifest viewmodel.DiffManifestResult) []string {
	lines := []string{
		ansiStyled("Manifest", ansiBold, ansiCyan),
		ansiStyled("  Status: ", ansiDim) + interactiveStatusText(manifest.Status),
		ansiStyled("  Path: ", ansiDim) + valueOrDash(manifest.Path),
		ansiStyled("  Kind: ", ansiDim) + valueOrDash(manifest.Kind),
		ansiStyled("  Subproject: ", ansiDim) + valueOrDash(manifest.Subproject),
		ansiStyled("  Package manager: ", ansiDim) + valueOrDash(manifest.PackageManager),
		"",
	}

	appendSection := func(title string, values []string) {
		lines = append(lines, ansiStyled(title, ansiBold, ansiMagenta))
		if len(values) == 0 {
			lines = append(lines, ansiStyled("  (none)", ansiDim))
			lines = append(lines, "")
			return
		}
		for _, value := range values {
			lines = append(lines, ansiStyled("  - ", ansiDim)+value)
		}
		lines = append(lines, "")
	}

	added := make([]string, 0, len(manifest.Added))
	for _, change := range manifest.Added {
		added = append(added, diffPackageDisplayName(change.Package))
	}
	changed := make([]string, 0, len(manifest.Changed))
	for _, change := range manifest.Changed {
		changed = append(changed, fmt.Sprintf("%s (%s -> %s)", diffPackageDisplayName(change.After), valueOrDash(change.Before.Version), valueOrDash(change.After.Version)))
	}
	removed := make([]string, 0, len(manifest.Removed))
	for _, change := range manifest.Removed {
		removed = append(removed, diffPackageDisplayName(change.Package))
	}

	appendSection("Added packages", added)
	appendSection("Changed packages", changed)
	appendSection("Removed packages", removed)
	return lines
}

func wrapLines(lines []string, width int) []string {
	if width < 1 {
		width = 1
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			out = append(out, "")
			continue
		}
		remaining := line
		for len(stripANSI(remaining)) > width {
			visible := stripANSI(remaining)
			out = append(out, visible[:width])
			remaining = visible[width:]
		}
		out = append(out, remaining)
	}
	return out
}

func wrapTextLines(value string, width int) []string {
	if width < 1 {
		return []string{""}
	}
	text := strings.TrimSpace(stripANSI(value))
	if text == "" {
		return []string{""}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	lines := make([]string, 0, len(words))
	current := words[0]
	for _, word := range words[1:] {
		candidate := current + " " + word
		if len(candidate) <= width {
			current = candidate
			continue
		}
		lines = append(lines, current)
		current = word
		for len(current) > width {
			lines = append(lines, current[:width])
			current = current[width:]
		}
	}
	lines = append(lines, current)
	return lines
}

func truncateToWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	visible := stripANSI(value)
	if len(visible) <= width {
		return value
	}
	if width <= 3 {
		return visible[:width]
	}
	return visible[:width-3] + "..."
}

func padRight(value string, width int) string {
	value = truncateToWidth(value, width)
	visibleWidth := len(stripANSI(value))
	if visibleWidth >= width {
		return value
	}
	return value + strings.Repeat(" ", width-visibleWidth)
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func interactiveStatusBadge(status string) string {
	label := " " + strings.ToUpper(valueOrDash(status)) + " "
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "manifest":
		return ansiStyled(label, ansiBgBlue, ansiYellow, ansiBold)
	case "self":
		return ansiStyled(label, ansiBgGreen, ansiWhite, ansiBold)
	case "parent":
		return ansiStyled(label, ansiBgCyan, ansiWhite, ansiBold)
	case "ancestor":
		return ansiStyled(label, ansiBgMagenta, ansiWhite, ansiBold)
	case "root":
		return ansiStyled(label, ansiBgBlue, ansiWhite, ansiBold)
	case "direct":
		return ansiStyled(label, ansiBgCyan, ansiWhite, ansiBold)
	case "transitive":
		return ansiStyled(label, ansiBgMagenta, ansiWhite, ansiBold)
	case "added":
		return ansiStyled(label, ansiBgGreen, ansiWhite, ansiBold)
	case "removed":
		return ansiStyled(label, ansiBgRed, ansiWhite, ansiBold)
	case "changed":
		return ansiStyled(label, ansiBgYellow, ansiBold)
	case "unchanged":
		return ansiStyled(label, ansiBgBlue, ansiWhite)
	default:
		return ansiStyled(label, ansiBgCyan, ansiBlue, ansiBold)
	}
}

func interactiveBadgeView(badge interactiveBadge) string {
	label := " " + strings.ToUpper(valueOrDash(badge.label)) + " "
	switch badge.kind {
	case "scope-runtime":
		return ansiStyled(label, ansiBgGreen, ansiWhite, ansiBold)
	case "scope-development":
		return ansiStyled(label, ansiBgYellow, ansiBold)
	case "severity-critical":
		return ansiStyled(label, ansiBgRed, ansiWhite, ansiBold)
	case "severity-high":
		return ansiStyled(label, ansiBgRed, ansiWhite)
	case "severity-medium":
		return ansiStyled(label, ansiBgYellow, ansiBold)
	case "severity-low":
		return ansiStyled(label, ansiBgCyan, ansiBlue, ansiBold)
	default:
		return ansiStyled(label, ansiBgCyan, ansiBlue, ansiBold)
	}
}

func interactiveSeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
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

func interactiveSeverityText(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return ansiStyled(s, ansiRed, ansiBold)
	case "high":
		return ansiStyled(s, ansiRed)
	case "medium":
		return ansiStyled(s, ansiYellow, ansiBold)
	case "low":
		return ansiStyled(s, ansiCyan)
	default:
		return ansiStyled(s, ansiDim)
	}
}

func interactiveStatusText(status string) string {
	status = valueOrDash(status)
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "self":
		return ansiStyled(status, ansiGreen, ansiBold)
	case "parent":
		return ansiStyled(status, ansiCyan, ansiBold)
	case "ancestor":
		return ansiStyled(status, ansiMagenta, ansiBold)
	case "root":
		return ansiStyled(status, ansiBlue, ansiBold)
	case "direct":
		return ansiStyled(status, ansiGreen, ansiBold)
	case "transitive":
		return ansiStyled(status, ansiMagenta, ansiBold)
	case "added":
		return ansiStyled(status, ansiGreen, ansiBold)
	case "removed":
		return ansiStyled(status, ansiRed, ansiBold)
	case "changed":
		return ansiStyled(status, ansiYellow, ansiBold)
	case "unchanged":
		return ansiStyled(status, ansiCyan, ansiBold)
	default:
		return ansiStyled(status, ansiWhite, ansiBold)
	}
}

func nextInteractiveRelationshipFilter(current string, explainMode bool) string {
	values := []string{"", "root", "direct", "transitive"}
	if explainMode {
		values = []string{"", "self", "parent", "ancestor", "root"}
	}
	return nextInteractiveFilterValue(current, values)
}

func nextInteractiveScopeFilter(current string) string {
	values := []string{"", "runtime", "development", "unset"}
	return nextInteractiveFilterValue(current, values)
}

func nextInteractiveSeverityFilter(current string) string {
	values := []string{"", "critical", "high", "medium", "low"}
	return nextInteractiveFilterValue(current, values)
}

// interactiveMaxSeverityByPkgID returns a map from package ID to the highest
// severity found across all vulnerability findings for that package.
func interactiveMaxSeverityByPkgID(findings []scan.Finding) map[string]string {
	result := make(map[string]string)
	for _, f := range findings {
		if f.Kind != scan.FindingKindVulnerability || f.Package == nil {
			continue
		}
		current := result[f.Package.ID]
		if interactiveSeverityRank(f.Severity) < interactiveSeverityRank(current) {
			result[f.Package.ID] = f.Severity
		}
	}
	return result
}

func nextInteractiveFilterValue(current string, values []string) string {
	for idx, value := range values {
		if value == current {
			return values[(idx+1)%len(values)]
		}
	}
	return values[0]
}

func filterInteractivePackageRows(rows []interactiveListPackageRow, relationshipFilter, scopeFilter string) []interactiveListPackageRow {
	if relationshipFilter == "" && scopeFilter == "" {
		return rows
	}
	filtered := make([]interactiveListPackageRow, 0, len(rows))
	for _, row := range rows {
		if relationshipFilter != "" && row.relationship != relationshipFilter {
			continue
		}
		if scopeFilter != "" {
			rowScope := row.scope
			if rowScope == "" {
				rowScope = "unset"
			}
			if rowScope != scopeFilter {
				continue
			}
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func interactiveExplainRelationships(graphValue *model.Graph, targetID string) (map[string]string, map[string]int) {
	labels := make(map[string]string)
	counts := map[string]int{
		"self":     0,
		"parent":   0,
		"ancestor": 0,
		"root":     0,
	}
	if graphValue == nil || strings.TrimSpace(targetID) == "" {
		return labels, counts
	}
	targetPkg, ok := graphValue.Package(targetID)
	if ok && targetPkg != nil {
		labels[targetID] = "self"
		counts["self"]++
	}
	rootIDs := make(map[string]struct{})
	for _, pkg := range graphValue.Roots() {
		if pkg != nil {
			rootIDs[pkg.ID] = struct{}{}
		}
	}
	parents, _ := graphValue.Dependents(targetID)
	parentIDs := make(map[string]struct{}, len(parents))
	for _, pkg := range parents {
		if pkg == nil || pkg.ID == targetID {
			continue
		}
		parentIDs[pkg.ID] = struct{}{}
		if _, isRoot := rootIDs[pkg.ID]; isRoot {
			labels[pkg.ID] = "root"
			counts["root"]++
			continue
		}
		labels[pkg.ID] = "parent"
		counts["parent"]++
	}
	for _, pkg := range graphValue.Packages() {
		if pkg == nil || pkg.ID == targetID {
			continue
		}
		if _, ok := labels[pkg.ID]; ok {
			continue
		}
		if _, isRoot := rootIDs[pkg.ID]; isRoot {
			labels[pkg.ID] = "root"
			counts["root"]++
			continue
		}
		labels[pkg.ID] = "ancestor"
		counts["ancestor"]++
	}
	return labels, counts
}

func interactivePackageBadges(row interactiveListPackageRow) []interactiveBadge {
	badges := make([]interactiveBadge, 0, 1)
	switch row.scope {
	case "runtime":
		badges = append(badges, interactiveBadge{label: row.scope, kind: "scope-runtime"})
	case "development":
		badges = append(badges, interactiveBadge{label: row.scope, kind: "scope-development"})
	}
	return badges
}
