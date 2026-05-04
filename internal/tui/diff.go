package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
)

func NewDiff(payload output.DiffResponse) *listModel {
	manifests := append([]output.DiffManifestResult(nil), payload.Results.Manifests...)
	sort.Slice(manifests, func(i, j int) bool {
		left := manifests[i]
		right := manifests[j]
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

	items := make([]listItem, 0, len(manifests))
	for _, manifest := range manifests {
		items = append(items, listItem{
			title:    render.DiffManifestDisplayLabel(manifest),
			subtitle: manifest.Status,
			details:  diffManifestDetails(manifest),
		})
	}

	return &listModel{
		title: fmt.Sprintf("Bomly Interactive Diff: %s -> %s", payload.Comparison.Base, payload.Comparison.Head),
		summary: []string{
			summaryLine("Manifest changes", []string{
				render.Style(fmt.Sprintf("added %d", payload.Summary.AddedManifestCount), render.Green, render.Bold),
				render.Style(fmt.Sprintf("changed %d", payload.Summary.ChangedManifestCount), render.Yellow, render.Bold),
				render.Style(fmt.Sprintf("unchanged %d", payload.Summary.UnchangedManifestCount), render.Cyan, render.Bold),
				render.Style(fmt.Sprintf("removed %d", payload.Summary.RemovedManifestCount), render.Red, render.Bold),
			}),
			summaryLine("Package changes", []string{
				render.Style(fmt.Sprintf("added %d", payload.Summary.AddedPackageCount), render.Green, render.Bold),
				render.Style(fmt.Sprintf("updated %d", payload.Summary.ChangedPackageCount), render.Yellow, render.Bold),
				render.Style(fmt.Sprintf("removed %d", payload.Summary.RemovedPackageCount), render.Red, render.Bold),
			}),
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps current result; Esc clears search",
		emptyState:     "No manifest changes were found.",
		items:          items,
	}
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
