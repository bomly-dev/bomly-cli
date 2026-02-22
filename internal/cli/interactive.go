package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	model "github.com/bomly-dev/bomly-cli/sdk"
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
	findings           []model.Finding
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
	var status string
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
