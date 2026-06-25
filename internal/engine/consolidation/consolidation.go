package consolidation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// ConsolidateGraphs merges resolved subproject graph containers while preserving manifest roots.
func ConsolidateGraphs(results []sdk.DetectionResult) (sdk.ConsolidatedGraph, error) {
	consolidated := sdk.ConsolidatedGraph{
		Graphs:      &sdk.GraphContainer{},
		Manifests:   make([]sdk.ConsolidatedManifest, 0, len(results)),
		Subprojects: make([]sdk.ConsolidatedSubproject, 0, len(results)),
	}
	selectedTarget, selectedManifests, err := selectManifestEntries(results)
	if err != nil {
		return sdk.ConsolidatedGraph{}, err
	}
	consolidated.ExecutionTarget = selectedTarget
	consolidated.Manifests = selectedManifests

	subprojectIndex := make(map[string]int)
	for _, selected := range selectedManifests {
		consolidated.Graphs.Entries = append(consolidated.Graphs.Entries, selected.Entry)

		subprojectKey := consolidatedSubprojectKey(selected.Subproject, selected.DetectorName)
		idx, exists := subprojectIndex[subprojectKey]
		if !exists {
			subprojectIndex[subprojectKey] = len(consolidated.Subprojects)
			consolidated.Subprojects = append(consolidated.Subprojects, sdk.ConsolidatedSubproject{
				Subproject:      selected.Subproject,
				DetectorName:    selected.DetectorName,
				RootManifestIDs: []string{selected.RootManifestID},
			})
			continue
		}
		consolidated.Subprojects[idx].RootManifestIDs = append(consolidated.Subprojects[idx].RootManifestIDs, selected.RootManifestID)
	}
	return consolidated, nil
}

type consolidatedEntryCandidate struct {
	entry          sdk.GraphEntry
	subproject     sdk.Subproject
	detectorName   string
	origin         sdk.DetectorOrigin
	technique      sdk.DetectorTechnique
	rootManifestID string
	priority       int
}

func selectManifestEntries(results []sdk.DetectionResult) (sdk.ExecutionTarget, []sdk.ConsolidatedManifest, error) {
	var executionTarget sdk.ExecutionTarget
	selectedEntries := make([]consolidatedEntryCandidate, 0)
	entryIndexByManifest := make(map[string]int)
	for _, result := range results {
		if result.Graphs == nil || result.Graphs.Len() == 0 {
			continue
		}
		candidateTarget := result.RootExecutionTarget
		if candidateTarget.Kind == "" {
			candidateTarget = result.SubprojectInfo.ExecutionTarget
		}
		if executionTarget.Kind == "" {
			executionTarget = candidateTarget
		} else if executionTarget != candidateTarget {
			return sdk.ExecutionTarget{}, nil, fmt.Errorf("cannot consolidate graphs from multiple execution targets")
		}

		for idx, entry := range result.Graphs.Entries {
			if err := validateGraphEntry(entry); err != nil {
				return sdk.ExecutionTarget{}, nil, fmt.Errorf("subproject %s entry %d: %w", result.SubprojectInfo.RelativePath, idx, err)
			}

			normalizedGraph, err := normalizeGraphPackageIdentity(entry.Graph)
			if err != nil {
				return sdk.ExecutionTarget{}, nil, fmt.Errorf("normalize graph identity for %s entry %d: %w", result.SubprojectInfo.RelativePath, idx, err)
			}
			if isCoreDetector(result.Origin) {
				// Rebase detector-relative location paths onto the subproject
				// root so diff-aware SARIF sees repository-relative paths. A
				// no-op for today's root-level subprojects (RelativePath ".").
				rebaseGraphLocations(normalizedGraph, result.SubprojectInfo.RelativePath)
			}
			manifest := normalizeSubprojectManifest(result.SubprojectInfo, entry.Manifest, idx, result.Origin)
			if err := ensureEntryRoot(normalizedGraph, manifest, idx); err != nil {
				return sdk.ExecutionTarget{}, nil, fmt.Errorf("ensure entry root for %s entry %d: %w", result.SubprojectInfo.RelativePath, idx, err)
			}
			candidate := consolidatedEntryCandidate{
				entry: sdk.GraphEntry{
					Graph:    normalizedGraph,
					Manifest: manifest,
				},
				subproject:     result.SubprojectInfo,
				detectorName:   result.DetectorName,
				technique:      result.Technique,
				rootManifestID: consolidatedEntryRootID(normalizedGraph, manifest, idx),
				priority:       ManifestDedupPriority(result.Origin),
			}

			manifestKey := manifestDedupKey(result.SubprojectInfo, manifest)
			existingIdx, exists := entryIndexByManifest[manifestKey]
			if !exists {
				entryIndexByManifest[manifestKey] = len(selectedEntries)
				selectedEntries = append(selectedEntries, candidate)
				continue
			}

			if candidate.priority < selectedEntries[existingIdx].priority {
				selectedEntries[existingIdx] = candidate
			}
		}
	}

	selectedManifests := make([]sdk.ConsolidatedManifest, 0, len(selectedEntries))
	for _, selected := range selectedEntries {
		selectedManifests = append(selectedManifests, sdk.ConsolidatedManifest{
			Entry:          selected.entry,
			Subproject:     selected.subproject,
			DetectorName:   selected.detectorName,
			Technique:      selected.technique,
			RootManifestID: selected.rootManifestID,
		})
	}
	return executionTarget, selectedManifests, nil
}

func normalizeSubprojectManifest(subproject sdk.Subproject, manifest sdk.ManifestMetadata, idx int, origin sdk.DetectorOrigin) sdk.ManifestMetadata {
	if strings.TrimSpace(manifest.Path) == "" {
		manifest.Path = subprojectManifestPath(subproject, idx)
	}
	manifest.Path = strings.ReplaceAll(strings.TrimSpace(manifest.Path), "\\", "/")
	if isCoreDetector(origin) {
		manifest.Path = normalizeNativeManifestPath(subproject, manifest.Path)
	}
	if strings.TrimSpace(string(manifest.Kind)) == "" {
		manifest.Kind = sdk.ManifestKind(subproject.PrimaryPackageManager().Name())
	}
	manifest.Kind = sdk.ManifestKind(strings.TrimSpace(string(manifest.Kind)))
	return manifest
}

// ManifestDedupPriority returns the precedence rank used when multiple
// detectors resolve the same manifest. Lower values win.
//
// Priority order:
// 0. External detectors
// 1. Core detectors (Bomly-native implementations)
// 2. Bundled third-party detectors (e.g. Syft fallback)
func ManifestDedupPriority(origin sdk.DetectorOrigin) int {
	switch origin {
	case sdk.ExternalOrigin:
		return 0
	case sdk.CoreOrigin:
		return 1
	case sdk.BundledOrigin:
		return 2
	}
	return 3
}

func isCoreDetector(origin sdk.DetectorOrigin) bool {
	return origin == sdk.CoreOrigin
}

func consolidatedSubprojectKey(subproject sdk.Subproject, detectorName string) string {
	return strings.Join([]string{subproject.RelativePath, subproject.PrimaryPackageManager().Name(), detectorName, subproject.ExecutionTarget.Location}, "::")
}

func subprojectManifestPath(subproject sdk.Subproject, idx int) string {
	label := strings.TrimSpace(subproject.RelativePath)
	if label == "" || label == "." {
		label = strings.TrimSpace(subproject.ExecutionTarget.Location)
	}
	if label == "" {
		return fmt.Sprintf("entry-%d", idx+1)
	}
	return strings.ReplaceAll(label, "\\", "/")
}

func validateGraphEntry(entry sdk.GraphEntry) error {
	if entry.Graph == nil {
		return errors.New("graph entry graph is nil")
	}
	return nil
}
