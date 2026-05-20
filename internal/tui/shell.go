package tui

import (
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
)

// TabBuild produces the listModel that backs a single tab. The shell calls
// it whenever the active tab is (re)rendered so the tab can read fresh
// state from the embedding command model.
type TabBuild func() *listModel

// TabSpec describes one tab in the shared TUI shell.
type TabSpec struct {
	ID    string
	Label string
	Build TabBuild
}

// ShellSpec configures a shellModel: a top-bar line, a list of tabs, and
// optional footer lines. Commands (scan, diff, explain) construct one and
// embed *shellModel to inherit tab cycling, the tab strip, and listModel
// delegation.
type ShellSpec struct {
	TopBar func() string
	Tabs   []TabSpec
	Footer func() (summary, legend string)
}

// shellModel owns the cross-command TUI chrome: which tab is active, the
// top-bar logo, the tab strip, and forwarding of listModel-level methods
// (search, scroll, move) to the active tab. Each command's model embeds
// *shellModel and supplies a ShellSpec at construction.
type shellModel struct {
	spec    ShellSpec
	active  int
	list    *listModel
	rebuild func() // optional override used by callers that need to refresh after state changes
}

func newShell(spec ShellSpec) *shellModel {
	s := &shellModel{spec: spec}
	s.Rebuild()
	return s
}

// Rebuild re-invokes the active tab's Build func. Call after the embedding
// model mutates any state that the tab reads (filters, expansion maps, ...).
func (s *shellModel) Rebuild() {
	if s == nil {
		return
	}
	if len(s.spec.Tabs) == 0 {
		s.list = nil
		return
	}
	if s.active < 0 || s.active >= len(s.spec.Tabs) {
		s.active = 0
	}
	s.list = s.spec.Tabs[s.active].Build()
	if s.list == nil {
		return
	}
	s.list.summary = append(s.shellSummaryLines(), s.list.summary...)
	if s.spec.Footer != nil {
		summary, legend := s.spec.Footer()
		if strings.TrimSpace(summary) != "" {
			s.list.footerSummary = summary
		}
		if strings.TrimSpace(legend) != "" {
			s.list.legend = legend
		}
		s.list.title = ""
	}
}

func (s *shellModel) shellSummaryLines() []string {
	out := make([]string, 0, 4)
	if s.spec.TopBar != nil {
		if line := strings.TrimRight(s.spec.TopBar(), " "); line != "" {
			out = append(out, line, "")
		}
	}
	out = append(out, s.TabLine(), "")
	return out
}

// TabLine renders the active-tab-highlighted "[1] Foo | [2] Bar" strip.
func (s *shellModel) TabLine() string {
	parts := make([]string, 0, len(s.spec.Tabs))
	for idx, tab := range s.spec.Tabs {
		text := fmt.Sprintf("[%d] %s", idx+1, tab.Label)
		if idx == s.active {
			parts = append(parts, render.Style(text, render.Yellow, render.Bold))
		} else {
			parts = append(parts, render.Style(text, render.Dim))
		}
	}
	return strings.Join(parts, render.Style(" | ", render.Dim))
}

// ActiveTabID returns the ID string of the active tab, or "" if there are no
// tabs. Embedding models use it to branch View() or specialize behavior.
func (s *shellModel) ActiveTabID() string {
	if s == nil || s.active < 0 || s.active >= len(s.spec.Tabs) {
		return ""
	}
	return s.spec.Tabs[s.active].ID
}

// List exposes the active listModel so the embedding command can poke at
// it (e.g. preserve selected index across rebuilds).
func (s *shellModel) List() *listModel { return s.list }

// CycleView advances to the next tab.
func (s *shellModel) CycleView() {
	if s == nil || len(s.spec.Tabs) == 0 {
		return
	}
	s.active = (s.active + 1) % len(s.spec.Tabs)
	s.Rebuild()
}

// SelectView jumps to the 1-indexed tab.
func (s *shellModel) SelectView(index int) {
	if s == nil || index < 1 || index > len(s.spec.Tabs) {
		return
	}
	s.active = index - 1
	s.Rebuild()
}

// View delegates to the active listModel. Embedding models can override
// when a tab wants a custom non-list renderer (e.g. scan's overview
// dashboard).
func (s *shellModel) View(width, height int) string {
	if s == nil || s.list == nil {
		return ""
	}
	return s.list.View(width, height)
}

func (s *shellModel) Move(delta int) {
	if s != nil && s.list != nil {
		s.list.Move(delta)
	}
}
func (s *shellModel) Home() {
	if s != nil && s.list != nil {
		s.list.Home()
	}
}
func (s *shellModel) End() {
	if s != nil && s.list != nil {
		s.list.End()
	}
}
func (s *shellModel) ScrollDetails(delta int) {
	if s != nil && s.list != nil {
		s.list.ScrollDetails(delta)
	}
}
func (s *shellModel) BeginSearch() {
	if s != nil && s.list != nil {
		s.list.BeginSearch()
	}
}
func (s *shellModel) AppendSearch(value string) {
	if s != nil && s.list != nil {
		s.list.AppendSearch(value)
	}
}
func (s *shellModel) BackspaceSearch() {
	if s != nil && s.list != nil {
		s.list.BackspaceSearch()
	}
}
func (s *shellModel) CancelSearch() {
	if s != nil && s.list != nil {
		s.list.CancelSearch()
	}
}
func (s *shellModel) ConfirmSearch() {
	if s != nil && s.list != nil {
		s.list.ConfirmSearch()
	}
}
func (s *shellModel) IsSearching() bool {
	if s == nil || s.list == nil {
		return false
	}
	return s.list.IsSearching()
}
