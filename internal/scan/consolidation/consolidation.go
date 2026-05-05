package consolidation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

// ConsolidateGraphs merges resolved subproject graph containers while preserving manifest roots.
func ConsolidateGraphs(results []model.DetectionResult) (model.ConsolidatedGraph, error) {
	consolidated := model.ConsolidatedGraph{
		Graphs:      &model.GraphContainer{},
		Manifests:   make([]model.ConsolidatedManifest, 0, len(results)),
		Subprojects: make([]model.ConsolidatedSubproject, 0, len(results)),
	}
	selectedTarget, selectedManifests, err := selectManifestEntries(results)
	if err != nil {
		return model.ConsolidatedGraph{}, err
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
			consolidated.Subprojects = append(consolidated.Subprojects, model.ConsolidatedSubproject{
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
	entry          model.GraphEntry
	subproject     model.Subproject
	detectorName   string
	componentType  model.ComponentType
	rootManifestID string
	priority       int
}

func selectManifestEntries(results []model.DetectionResult) (model.ExecutionTarget, []model.ConsolidatedManifest, error) {
	var executionTarget model.ExecutionTarget
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
			return model.ExecutionTarget{}, nil, fmt.Errorf("cannot consolidate graphs from multiple execution targets")
		}

		for idx, entry := range result.Graphs.Entries {
			if err := validateGraphEntry(entry); err != nil {
				return model.ExecutionTarget{}, nil, fmt.Errorf("subproject %s entry %d: %w", result.SubprojectInfo.RelativePath, idx, err)
			}

			normalizedGraph, err := normalizeGraphPackageIdentity(entry.Graph)
			if err != nil {
				return model.ExecutionTarget{}, nil, fmt.Errorf("normalize graph identity for %s entry %d: %w", result.SubprojectInfo.RelativePath, idx, err)
			}
			manifest := normalizeSubprojectManifest(result.SubprojectInfo, entry.Manifest, idx, result.ComponentType, result.DetectorName)
			if err := ensureEntryRoot(normalizedGraph, manifest, idx); err != nil {
				return model.ExecutionTarget{}, nil, fmt.Errorf("ensure entry root for %s entry %d: %w", result.SubprojectInfo.RelativePath, idx, err)
			}
			candidate := consolidatedEntryCandidate{
				entry: model.GraphEntry{
					Graph:    normalizedGraph,
					Manifest: manifest,
				},
				subproject:     result.SubprojectInfo,
				detectorName:   result.DetectorName,
				componentType:  result.ComponentType,
				rootManifestID: consolidatedEntryRootID(normalizedGraph, manifest, idx),
				priority:       ManifestDedupPriority(result.ComponentType, result.DetectorName),
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

	selectedManifests := make([]model.ConsolidatedManifest, 0, len(selectedEntries))
	for _, selected := range selectedEntries {
		selectedManifests = append(selectedManifests, model.ConsolidatedManifest{
			Entry:          selected.entry,
			Subproject:     selected.subproject,
			DetectorName:   selected.detectorName,
			ComponentType:  selected.componentType,
			RootManifestID: selected.rootManifestID,
		})
	}
	return executionTarget, selectedManifests, nil
}

func normalizeSubprojectManifest(subproject model.Subproject, manifest model.ManifestMetadata, idx int, detectorType model.ComponentType, detectorName string) model.ManifestMetadata {
	if strings.TrimSpace(manifest.Path) == "" {
		manifest.Path = subprojectManifestPath(subproject, idx)
	}
	manifest.Path = strings.ReplaceAll(strings.TrimSpace(manifest.Path), "\\", "/")
	if isNativeDetector(detectorType, detectorName) {
		manifest.Path = normalizeNativeManifestPath(subproject, manifest.Path)
	}
	if strings.TrimSpace(manifest.Kind) == "" {
		manifest.Kind = subproject.PrimaryPackageManager().Name()
	}
	manifest.Kind = strings.TrimSpace(manifest.Kind)
	return manifest
}

// ManifestDedupPriority returns the precedence rank used when multiple
// detectors resolve the same manifest. Lower values win.
//
// Priority order:
// 0. Native and lockfile-parser detectors
// 1. Plugin detectors and non-Syft third-party detectors
// 2. Syft fallback detector
func ManifestDedupPriority(detectorType model.ComponentType, detectorName string) int {
	switch effectiveDetectorType(detectorType, detectorName) {
	case model.NativeComponent, model.LockfileParserComponent:
		return 0
	case model.ThirdPartyComponent:
		if strings.EqualFold(strings.TrimSpace(detectorName), detectors.NameSyft) {
			return 2
		}
		return 1
	case model.PluginComponent:
		return 1
	default:
		return 1
	}
}

func isNativeDetector(detectorType model.ComponentType, detectorName string) bool {
	effectiveType := effectiveDetectorType(detectorType, detectorName)
	return effectiveType == model.NativeComponent || effectiveType == model.LockfileParserComponent
}

func effectiveDetectorType(detectorType model.ComponentType, detectorName string) model.ComponentType {
	if detectorType != "" {
		return detectorType
	}
	if strings.EqualFold(strings.TrimSpace(detectorName), detectors.NameSyft) {
		return model.ThirdPartyComponent
	}
	return model.NativeComponent
}

func consolidatedSubprojectKey(subproject model.Subproject, detectorName string) string {
	return strings.Join([]string{subproject.RelativePath, subproject.PrimaryPackageManager().Name(), detectorName, subproject.ExecutionTarget.Location}, "::")
}

func subprojectManifestPath(subproject model.Subproject, idx int) string {
	label := strings.TrimSpace(subproject.RelativePath)
	if label == "" || label == "." {
		label = strings.TrimSpace(subproject.ExecutionTarget.Location)
	}
	if label == "" {
		return fmt.Sprintf("entry-%d", idx+1)
	}
	return strings.ReplaceAll(label, "\\", "/")
}

func validateGraphEntry(entry model.GraphEntry) error {
	if entry.Graph == nil {
		return errors.New("graph entry graph is nil")
	}
	return nil
}
