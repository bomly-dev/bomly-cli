package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
)

type diffTab string

const (
	diffTabOverview diffTab = "overview"
	diffTabAdded    diffTab = "added"
	diffTabRemoved  diffTab = "removed"
	diffTabChanged  diffTab = "changed"
)

type diffModel struct {
	*listModel
	payload output.DiffResponse
	active  diffTab
}

func NewDiff(payload output.DiffResponse) *diffModel {
	model := &diffModel{payload: payload, active: diffTabOverview}
	model.listModel = model.buildList()
	return model
}

func (m *diffModel) CycleView() {
	tabs := diffTabs()
	for idx, tab := range tabs {
		if tab == m.active {
			m.active = tabs[(idx+1)%len(tabs)]
			m.listModel = m.buildList()
			return
		}
	}
	m.active = diffTabOverview
	m.listModel = m.buildList()
}

func (m *diffModel) SelectView(index int) {
	tabs := diffTabs()
	if index < 1 || index > len(tabs) {
		return
	}
	m.active = tabs[index-1]
	m.listModel = m.buildList()
}

func diffTabs() []diffTab {
	return []diffTab{diffTabOverview, diffTabAdded, diffTabRemoved, diffTabChanged}
}

func (m *diffModel) buildList() *listModel {
	switch m.active {
	case diffTabAdded:
		return m.buildPackageTab(diffTabAdded)
	case diffTabRemoved:
		return m.buildPackageTab(diffTabRemoved)
	case diffTabChanged:
		return m.buildPackageTab(diffTabChanged)
	default:
		return m.buildOverviewTab()
	}
}

func (m *diffModel) buildOverviewTab() *listModel {
	manifests := sortedDiffManifests(m.payload.Results.Manifests)
	items := make([]listItem, 0, len(manifests))
	for _, manifest := range manifests {
		items = append(items, listItem{
			title:    render.DiffManifestDisplayLabel(manifest),
			subtitle: manifest.Status,
			details:  diffManifestDetails(manifest),
		})
	}
	return &listModel{
		title:          "",
		summary:        m.diffSummaryLines(),
		listTitle:      fmt.Sprintf("Manifests (%d)", len(items)),
		detailTitle:    "Manifest Details",
		topPanels:      m.diffTopPanels(),
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Tab or 1-4 switches tabs; Enter keeps current result; Esc clears search",
		emptyState:     "No manifest changes were found.",
		items:          items,
	}
}

func (m *diffModel) buildPackageTab(tab diffTab) *listModel {
	items := make([]listItem, 0)
	for _, manifest := range sortedDiffManifests(m.payload.Results.Manifests) {
		switch tab {
		case diffTabAdded:
			for _, change := range manifest.Added {
				label := render.DiffPackageDisplayName(change.Package)
				items = append(items, listItem{title: label, subtitle: string(tab), details: diffPackageDetails("Added package", manifest, label, "", "")})
			}
		case diffTabRemoved:
			for _, change := range manifest.Removed {
				label := render.DiffPackageDisplayName(change.Package)
				items = append(items, listItem{title: label, subtitle: string(tab), details: diffPackageDetails("Removed package", manifest, label, "", "")})
			}
		case diffTabChanged:
			for _, change := range manifest.Changed {
				before := render.DiffPackageDisplayName(change.Before)
				after := render.DiffPackageDisplayName(change.After)
				title := after
				if title == "" {
					title = before
				}
				items = append(items, listItem{title: title, subtitle: string(tab), details: diffPackageDetails("Changed package", manifest, title, before, after)})
			}
		}
	}
	return &listModel{
		title:          "",
		summary:        m.diffSummaryLines(),
		listTitle:      fmt.Sprintf("%s Packages (%d)", titleCase(string(tab)), len(items)),
		detailTitle:    "Package Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Tab or 1-4 switches tabs; Enter keeps current result; Esc clears search",
		emptyState:     fmt.Sprintf("No %s packages were found.", string(tab)),
		items:          items,
	}
}

func sortedDiffManifests(manifests []output.DiffManifestResult) []output.DiffManifestResult {
	sorted := append([]output.DiffManifestResult(nil), manifests...)
	sort.Slice(sorted, func(i, j int) bool {
		left := sorted[i]
		right := sorted[j]
		if left.Status != right.Status {
			return render.DiffManifestStatusOrder(left.Status) < render.DiffManifestStatusOrder(right.Status)
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.PackageManager != right.PackageManager {
			return left.PackageManager < right.PackageManager
		}
		return left.Subproject < right.Subproject
	})
	return sorted
}

func (m *diffModel) diffSummaryLines() []string {
	return []string{
		diffTopBar(m.payload),
		"",
		m.diffTabLine(),
		"",
	}
}

func (m *diffModel) diffTabLine() string {
	labels := []struct {
		tab   diffTab
		label string
	}{
		{diffTabOverview, "Overview"},
		{diffTabAdded, "Added"},
		{diffTabRemoved, "Removed"},
		{diffTabChanged, "Changed"},
	}
	parts := make([]string, 0, len(labels))
	for idx, item := range labels {
		text := fmt.Sprintf("[%d] %s", idx+1, item.label)
		if item.tab == m.active {
			parts = append(parts, render.Style(text, render.Yellow, render.Bold))
		} else {
			parts = append(parts, render.Style(text, render.Dim))
		}
	}
	return strings.Join(parts, render.Style(" | ", render.Dim))
}

func (m *diffModel) diffTopPanels() []listPanel {
	return []listPanel{
		{title: "Manifest Changes", lines: []string{
			render.Style(fmt.Sprintf("%d Added", m.payload.Summary.AddedManifestCount), render.Green, render.Bold),
			render.Style(fmt.Sprintf("%d Changed", m.payload.Summary.ChangedManifestCount), render.Yellow, render.Bold),
			render.Style(fmt.Sprintf("%d Removed", m.payload.Summary.RemovedManifestCount), render.Red, render.Bold),
			render.Style(fmt.Sprintf("%d Unchanged", m.payload.Summary.UnchangedManifestCount), render.Cyan, render.Bold),
		}, color: render.Cyan, weight: 1},
		{title: "Package Changes", lines: []string{
			render.Style(fmt.Sprintf("%d Added", m.payload.Summary.AddedPackageCount), render.Green, render.Bold),
			render.Style(fmt.Sprintf("%d Changed", m.payload.Summary.ChangedPackageCount), render.Yellow, render.Bold),
			render.Style(fmt.Sprintf("%d Removed", m.payload.Summary.RemovedPackageCount), render.Red, render.Bold),
		}, color: render.Magenta, weight: 1},
	}
}

func diffTopBar(payload output.DiffResponse) string {
	targetParts := []string{
		render.Style(valueOrDash(payload.Project.Name), render.White, render.Bold),
		render.Style(targetKindLabel(payload.Project), render.Dim),
	}
	if payload.Project.TargetRef != "" {
		targetParts = append(targetParts, render.Style("ref: "+payload.Project.TargetRef, render.Cyan, render.Bold))
	}
	targetParts = append(targetParts, render.Style(payload.Comparison.Base+" -> "+payload.Comparison.Head, render.Cyan, render.Bold))
	return render.Style(" bomly ", render.BgCyan, render.Blue, render.Bold) + " " +
		render.Style("DIFF", render.BgBlue, render.White, render.Bold) + " " +
		strings.Join(targetParts, render.Style(" | ", render.Dim))
}

func diffPackageDetails(title string, manifest output.DiffManifestResult, label, before, after string) []string {
	lines := []string{
		render.Style(title, render.Bold, render.Cyan),
		"",
		render.Style("  Package: ", render.Dim) + valueOrDash(label),
		render.Style("  Manifest: ", render.Dim) + render.DiffManifestDisplayLabel(manifest),
		render.Style("  Status: ", render.Dim) + statusText(manifest.Status),
		render.Style("  Ecosystem: ", render.Dim) + valueOrDash(manifest.Ecosystem),
		render.Style("  Package manager: ", render.Dim) + valueOrDash(manifest.PackageManager),
	}
	if before != "" || after != "" {
		lines = append(lines,
			"",
			render.Style("Version Change", render.Bold, render.Magenta),
			"",
			render.Style("  Before: ", render.Dim)+valueOrDash(before),
			render.Style("  After: ", render.Dim)+valueOrDash(after),
		)
	}
	return lines
}

func summaryLine(label string, values []string) string {
	return render.Style(label+": ", render.Dim) + strings.Join(values, render.Style("  |  ", render.Dim))
}

func diffManifestDetails(manifest output.DiffManifestResult) []string {
	lines := []string{
		render.Style("Manifest", render.Bold, render.Cyan),
		render.Style("  Status: ", render.Dim) + statusText(manifest.Status),
		render.Style("  Path: ", render.Dim) + valueOrDash(manifest.Path),
		render.Style("  Kind: ", render.Dim) + valueOrDash(manifest.Kind),
		render.Style("  Subproject: ", render.Dim) + valueOrDash(manifest.Subproject),
		render.Style("  Ecosystem: ", render.Dim) + valueOrDash(manifest.Ecosystem),
		render.Style("  Package manager: ", render.Dim) + valueOrDash(manifest.PackageManager),
		"",
	}

	appendSection := func(title string, values []string) {
		lines = append(lines, render.Style(title, render.Bold, render.Magenta))
		if len(values) == 0 {
			lines = append(lines, render.Style("  (none)", render.Dim))
			lines = append(lines, "")
			return
		}
		for _, value := range values {
			lines = append(lines, render.Style("  - ", render.Dim)+value)
		}
		lines = append(lines, "")
	}

	added := make([]string, 0, len(manifest.Added))
	for _, change := range manifest.Added {
		added = append(added, render.DiffPackageDisplayName(change.Package))
	}
	changed := make([]string, 0, len(manifest.Changed))
	for _, change := range manifest.Changed {
		changed = append(changed, fmt.Sprintf("%s (%s -> %s)", render.DiffPackageDisplayName(change.After), valueOrDash(change.Before.Version), valueOrDash(change.After.Version)))
	}
	removed := make([]string, 0, len(manifest.Removed))
	for _, change := range manifest.Removed {
		removed = append(removed, render.DiffPackageDisplayName(change.Package))
	}

	appendSection("Added packages", added)
	appendSection("Changed packages", changed)
	appendSection("Removed packages", removed)
	return lines
}
