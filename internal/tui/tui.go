package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

// ErrNotATerminal is returned by Run when stdin or stderr is not an
// attached terminal. Callers (the CLI) typically translate this into an
// invalid-input exit code.
var ErrNotATerminal = errors.New("--interactive requires a terminal stdin and stderr")

type Model interface {
	View(width, height int) string
	Move(delta int)
	Home()
	End()
}

type filterModel interface {
	Model
	CycleRelationshipFilter()
	CycleScopeFilter()
	CycleSeverityFilter()
	CycleEcosystemFilter()
}

type tabbedModel interface {
	CycleView()
}

type numberedTabModel interface {
	SelectView(index int)
}

type searchModel interface {
	Model
	BeginSearch()
	AppendSearch(value string)
	BackspaceSearch()
	CancelSearch()
	ConfirmSearch()
	IsSearching() bool
}

type navigationModel interface {
	OpenSelected()
	GoBack()
	CanGoBack() bool
}

type toggleModel interface {
	ToggleSelected()
}

type treeControlModel interface {
	ExpandSelected()
	CollapseSelected()
	ExpandAll()
	CollapseAll()
}

type groupModel interface {
	CycleGroup()
}

type detailScrollModel interface {
	ScrollDetails(delta int)
}

type listItem struct {
	title    string
	subtitle string
	badges   []badge
	details  []string
	children []listItem
	expanded bool
	key      string
	tree     string
	depth    int
	canOpen  bool
}

type badge struct {
	label string
	kind  string
}

type listModel struct {
	title          string
	summary        []string
	controls       []string
	navigationHelp string
	filterHelp     string
	emptyState     string
	listTitle      string
	listHeader     string
	detailTitle    string
	topPanels      []listPanel
	items          []listItem
	selected       int
	scrollOffset   int
	detailOffset   int
	searching      bool
	searchQuery    string
	searchMatch    bool
	footerSummary  string
	legend         string
	// bodyOverride, when non-nil, replaces the standard list-and-detail body
	// region with a caller-rendered block of `height` rows of `width` columns.
	// The shell chrome (title, summary, controls, topPanels, footer) renders
	// exactly as if the override were absent; only the middle band changes.
	bodyOverride func(width, height int) []string
}

type listPanel struct {
	title  string
	lines  []string
	color  string
	weight int
}

const interactiveCommonNavigationHelp = "Up/Down or j/k move; PgUp/PgDn or Ctrl+u/Ctrl+d scroll details; Home/End or g/G jump; q quits"

type listPackageRow struct {
	id               string
	rootID           string
	targetID         string
	displayName      string
	version          string
	scope            string
	ecosystem        string
	relationship     string
	purl             string
	repeated         bool
	detectorName     string
	origin           string
	technique        string
	packageManagers  string
	plannedDetectors string
	relativePath     string
	targetKind       string
	targetLocation   string
	depth            int
	tree             string
}

type rootDependencyGroup struct {
	direct     []*sdk.Package
	transitive []*sdk.Package
}

type scanMode string

const (
	interactiveScanModeManifests  scanMode = "manifests"
	interactiveScanModeComponents scanMode = "components"
)

type scanView string

const (
	interactiveScanViewOverview scanView = "overview"
	interactiveScanViewPackages scanView = "packages"
	interactiveScanViewVulns    scanView = "vulnerabilities"
	interactiveScanViewLicenses scanView = "licenses"
	interactiveScanViewFindings scanView = "findings"
	interactiveScanViewPosture  scanView = "posture"
	interactiveScanViewSource   scanView = "source"
)

type scanModel struct {
	*shellModel

	titlePrefix           string
	project               output.ProjectDescriptor
	graphValue            *sdk.Graph
	explainMode           bool
	manifests             []listPackageRow
	manifestByID          map[string]listPackageRow
	mode                  scanMode
	findings              []sdk.Finding
	enrichEnabled         bool
	currentManifestID     string
	allowManifestExit     bool
	relationshipFilter    string
	scopeFilter           string
	severityFilter        string
	ecosystemFilter       string
	explainQuery          string
	sourceExpanded        map[string]bool
	componentExpanded     map[string]bool
	vulnerabilityGroup    string
	vulnerabilityExpanded map[string]bool
	licenseGroup          string
	licenseExpanded       map[string]bool
	findingGroup          string
	findingExpanded       map[string]bool
}

type teaModel struct {
	inner       Model
	width       int
	height      int
	quitting    bool
	confirmQuit bool
}

func Run(stdin io.Reader, stderr io.Writer, model Model) error {
	inFile, err := terminalFile(stdin)
	if err != nil {
		return ErrNotATerminal
	}
	outFile, err := terminalFile(stderr)
	if err != nil {
		return ErrNotATerminal
	}

	stdinFD := int(inFile.Fd())
	stdoutFD := int(outFile.Fd())
	if !term.IsTerminal(stdinFD) {
		return ErrNotATerminal
	}
	if !term.IsTerminal(stdoutFD) {
		return ErrNotATerminal
	}

	program := tea.NewProgram(
		&teaModel{inner: model, width: 100, height: 30},
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

func (m *teaModel) Init() tea.Cmd {
	return nil
}

func (m *teaModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if searchModel, ok := m.inner.(searchModel); ok && searchModel.IsSearching() {
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
			if searchModel, ok := m.inner.(searchModel); ok {
				searchModel.BeginSearch()
			}
		case "r":
			if filterModel, ok := m.inner.(filterModel); ok {
				filterModel.CycleRelationshipFilter()
			}
		case "s":
			if filterModel, ok := m.inner.(filterModel); ok {
				filterModel.CycleScopeFilter()
			}
		case "g":
			if groupModel, ok := m.inner.(groupModel); ok {
				groupModel.CycleGroup()
			} else {
				m.inner.Home()
			}
		case "v":
			if filterModel, ok := m.inner.(filterModel); ok {
				filterModel.CycleSeverityFilter()
			}
		case "e":
			if filterModel, ok := m.inner.(filterModel); ok {
				filterModel.CycleEcosystemFilter()
			}
		case "enter":
			if m.confirmQuit {
				m.quitting = true
				return m, tea.Quit
			}
			if toggleModel, ok := m.inner.(toggleModel); ok {
				toggleModel.ToggleSelected()
			}
			if navigationModel, ok := m.inner.(navigationModel); ok {
				navigationModel.OpenSelected()
			}
		case "1", "2", "3", "4", "5", "6":
			if tabModel, ok := m.inner.(numberedTabModel); ok {
				tabModel.SelectView(int(msg.String()[0] - '0'))
			}
		case "right", "l":
			if treeModel, ok := m.inner.(treeControlModel); ok {
				treeModel.ExpandSelected()
			}
		case "]":
			if treeModel, ok := m.inner.(treeControlModel); ok {
				treeModel.ExpandAll()
			}
		case "[":
			if treeModel, ok := m.inner.(treeControlModel); ok {
				treeModel.CollapseAll()
			}
		case "left":
			if m.confirmQuit {
				m.confirmQuit = false
				return m, nil
			}
			if treeModel, ok := m.inner.(treeControlModel); ok {
				treeModel.CollapseSelected()
			}
		case "h", "backspace":
			if m.confirmQuit {
				m.confirmQuit = false
				return m, nil
			}
			if navigationModel, ok := m.inner.(navigationModel); ok && navigationModel.CanGoBack() {
				navigationModel.GoBack()
			}
		case "up", "k":
			m.inner.Move(-1)
		case "down", "j":
			m.inner.Move(1)
		case "pgup", "ctrl+u":
			if detailModel, ok := m.inner.(detailScrollModel); ok {
				detailModel.ScrollDetails(-1)
			}
		case "pgdown", "ctrl+d":
			if detailModel, ok := m.inner.(detailScrollModel); ok {
				detailModel.ScrollDetails(1)
			}
		case "home":
			m.inner.Home()
		case "end", "G", "shift+g":
			m.inner.End()
		case "tab":
			if tabbedModel, ok := m.inner.(tabbedModel); ok {
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

func (m *teaModel) View() string {
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
	confirmation := render.Style(" Exit Bomly interactive mode? Enter confirms, Esc/Backspace cancels. ", render.BgRed, render.White, render.Bold)
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

func (m *listModel) Move(delta int) {
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

func (m *listModel) Home() {
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

func (m *listModel) End() {
	visible := m.visibleItemIndices()
	if len(visible) == 0 {
		m.selected = 0
		m.scrollOffset = 0
		return
	}
	m.selected = visible[len(visible)-1]
	m.detailOffset = 0
}

func (m *listModel) ScrollDetails(delta int) {
	if delta == 0 {
		return
	}
	m.detailOffset += delta
	if m.detailOffset < 0 {
		m.detailOffset = 0
	}
}

func (m *listModel) BeginSearch() {
	m.searching = true
	m.searchQuery = ""
	m.searchMatch = true
	m.scrollOffset = 0
}

func (m *listModel) AppendSearch(value string) {
	if !m.searching {
		return
	}
	m.searchQuery += value
	m.jumpToSearchMatch()
}

func (m *listModel) BackspaceSearch() {
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

func (m *listModel) CancelSearch() {
	m.searching = false
	m.searchQuery = ""
	m.searchMatch = true
	m.scrollOffset = 0
}

func (m *listModel) ConfirmSearch() {
	m.searching = false
	m.scrollOffset = 0
}

func (m *listModel) IsSearching() bool {
	return m.searching
}

func (m *listModel) View(width, height int) string {
	if width < 60 {
		width = 60
	}
	if height < 12 {
		height = 12
	}

	var lines []string
	if strings.TrimSpace(m.title) != "" {
		lines = append(lines, truncateToWidth(render.Style(" "+m.title+" ", render.BgBlue, render.White, render.Bold), width))
	}
	for _, summaryLine := range m.summary {
		lines = append(lines, truncateToWidth(summaryLine, width))
	}
	if len(m.controls) > 0 {
		for idx, controlLine := range m.controls {
			lines = append(lines, truncateToWidth(controlLine, width))
			if idx < len(m.controls)-1 {
				lines = append(lines, "")
			}
		}
	}
	if m.searching {
		if len(m.controls) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, truncateToWidth(m.searchLine(width), width))
	}
	if len(m.controls) > 0 || m.searching {
		lines = append(lines, "")
	}
	footerLines := m.footerLines(width)

	bodyHeight := height - len(lines) - len(footerLines)
	topPanelLines := renderListPanels(m.topPanels, width)
	if len(topPanelLines) > 0 {
		bodyHeight -= len(topPanelLines) + 1
	}
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	if len(topPanelLines) > 0 {
		lines = append(lines, topPanelLines...)
		lines = append(lines, "")
	}

	if m.bodyOverride != nil {
		body := m.bodyOverride(width, bodyHeight)
		for i := 0; i < bodyHeight; i++ {
			if i < len(body) {
				lines = append(lines, body[i])
			} else {
				lines = append(lines, "")
			}
		}
		lines = append(lines, footerLines...)
		return strings.Join(lines, "\n")
	}

	visible := m.visibleItemIndices()
	if len(visible) == 0 {
		lines = append(lines, boxView("Empty", []string{render.Style(m.emptyState, render.Yellow, render.Bold)}, width, bodyHeight, render.Yellow)...)
		lines = append(lines, footerLines...)
		return strings.Join(lines, "\n")
	}

	fullWidthList := strings.TrimSpace(m.detailTitle) == "-"
	listWidth := width / 2
	detailWidth := width - listWidth - 1
	if fullWidthList {
		listWidth = width
		detailWidth = 0
	} else {
		if listWidth < 28 {
			listWidth = 28
		}
		if detailWidth < 20 {
			detailWidth = 20
			listWidth = width - detailWidth - 1
		}
	}

	selectedIndex := visible[m.selectedVisibleIndex(visible)]
	contentHeight := bodyHeight - 2
	if contentHeight < 1 {
		contentHeight = 1
	}
	listContentHeight := contentHeight
	if strings.TrimSpace(m.listHeader) != "" {
		listContentHeight--
	}
	listLines := m.visibleListLines(listWidth-2, listContentHeight, visible)
	if strings.TrimSpace(m.listHeader) != "" {
		listLines = append([]string{render.Style(truncateToWidth(m.listHeader, listWidth-2), render.Dim, render.Bold)}, listLines...)
	}
	detailLines := []string{}
	if !fullWidthList {
		detailLines = m.visibleDetailLines(m.items[selectedIndex].details, detailWidth-2, contentHeight)
	}
	if len(detailLines) < bodyHeight {
		detailLines = append(detailLines, make([]string, bodyHeight-len(detailLines))...)
	}

	leftTitle := valueOrDefault(m.listTitle, "List")
	rightTitle := valueOrDefault(m.detailTitle, "Details")
	leftBox := boxView(leftTitle, listLines, listWidth, bodyHeight, render.Cyan)
	if strings.TrimSpace(m.detailTitle) == "-" {
		for idx := 0; idx < bodyHeight; idx++ {
			lines = append(lines, leftBox[idx])
		}
	} else {
		rightBox := boxView(rightTitle, detailLines, detailWidth, bodyHeight, render.Magenta)
		for idx := 0; idx < bodyHeight; idx++ {
			lines = append(lines, leftBox[idx]+" "+rightBox[idx])
		}
	}

	lines = append(lines, footerLines...)
	return strings.Join(lines, "\n")
}

func renderListPanels(panels []listPanel, width int) []string {
	if len(panels) == 0 {
		return nil
	}
	gap := 1
	totalGap := gap * (len(panels) - 1)
	available := width - totalGap
	if available < len(panels)*12 {
		return nil
	}
	totalWeight := 0
	maxContent := 1
	for _, panel := range panels {
		weight := panel.weight
		if weight <= 0 {
			weight = 1
		}
		totalWeight += weight
		if len(panel.lines) > maxContent {
			maxContent = len(panel.lines)
		}
	}
	panelHeight := maxContent + 2
	rendered := make([][]string, 0, len(panels))
	used := 0
	for idx, panel := range panels {
		weight := panel.weight
		if weight <= 0 {
			weight = 1
		}
		panelWidth := available * weight / totalWeight
		if idx == len(panels)-1 {
			panelWidth = available - used
		}
		used += panelWidth
		color := panel.color
		if color == "" {
			color = render.Cyan
		}
		rendered = append(rendered, boxView(panel.title, panel.lines, panelWidth, panelHeight, color))
	}
	out := make([]string, 0, panelHeight)
	for row := 0; row < panelHeight; row++ {
		parts := make([]string, 0, len(rendered))
		for idx := range rendered {
			parts = append(parts, rendered[idx][row])
		}
		out = append(out, strings.Join(parts, strings.Repeat(" ", gap)))
	}
	return out
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (m *listModel) footerLines(width int) []string {
	if strings.TrimSpace(m.footerSummary) != "" || strings.TrimSpace(m.legend) != "" {
		lines := make([]string, 0, 2)
		if strings.TrimSpace(m.footerSummary) != "" {
			lines = append(lines, statusBar(m.footerSummary, width))
		}
		if strings.TrimSpace(m.legend) != "" {
			lines = append(lines, centerLine(m.legend, width))
		}
		return lines
	}
	lines := helpLines(m.navigationHelp, m.filterHelp, width)
	if len(lines) == 0 {
		return []string{""}
	}
	for idx, line := range lines {
		lines[idx] = truncateToWidth(render.Style(line, render.Dim), width)
	}
	return lines
}

func helpLines(navigationHelp, filterHelp string, width int) []string {
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

func (m *listModel) searchLine(width int) string {
	var status string
	switch {
	case strings.TrimSpace(m.searchQuery) == "":
		status = render.Style("type to filter and jump", render.Blue, render.Bold)
	case !m.searchMatch:
		status = render.Style("no matches", render.Red, render.Bold)
	default:
		status = render.Style(fmt.Sprintf("%d match(es)", len(m.visibleItemIndices())), render.Blue, render.Bold)
	}
	line := render.Style("Search ", render.Dim) +
		render.Style("/"+m.searchQuery, render.White, render.Bold) +
		render.Style("  Enter: keep  Esc: clear  Backspace: edit  ", render.Dim) +
		status
	return truncateToWidth(line, width)
}

func (m *listModel) visibleListLines(width, height int, visible []int) []string {
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
		item := m.items[idx]
		tree := item.tree
		if tree == "" && item.depth > 0 {
			tree = strings.Repeat("   ", item.depth)
		}
		marker := "  "
		if item.canOpen {
			marker = "▸ "
			if item.expanded {
				marker = "▾ "
			}
		}
		selector := "  "
		prefix := render.Style(selector+tree+marker, render.Dim)
		title := render.Style(m.items[idx].title, render.White)
		if idx == m.selected {
			selector = "> "
			prefix = render.Style(selector+tree+marker, render.BgBlue, render.White, render.Bold)
			title = render.Style(m.items[idx].title, render.White, render.Bold)
		}
		line := prefix + title
		if m.items[idx].subtitle != "" {
			line += " " + statusBadge(m.items[idx].subtitle)
		}
		for _, badge := range m.items[idx].badges {
			line += " " + badgeView(badge)
		}
		out = append(out, truncateToWidth(line, width))
	}
	for len(out) < height {
		out = append(out, "")
	}
	return out
}

func (m *listModel) visibleDetailLines(lines []string, width, height int) []string {
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

func (m *listModel) jumpToSearchMatch() {
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

func (m *listModel) visibleItemIndices() []int {
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
		if itemMatches(item, query) {
			indices = append(indices, idx)
		}
	}
	return indices
}

func (m *listModel) selectedVisibleIndex(visible []int) int {
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

func itemMatches(item listItem, query string) bool {
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
