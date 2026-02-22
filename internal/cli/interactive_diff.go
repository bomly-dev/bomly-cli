package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

func newDiffInteractiveModel(payload output.DiffResponse) *interactiveListModel {
	manifests := append([]output.DiffManifestResult(nil), payload.Results.Manifests...)
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

func interactiveDiffManifestDetails(manifest output.DiffManifestResult) []string {
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
