package yarn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/sdk"
)

type yarnLockEntry struct {
	Name         string
	Version      string
	Resolved     string
	Integrity    string
	Selectors    []string
	Dependencies map[string]string
}

func depGraphFromYarnLockfile(projectPath string) (*sdk.Graph, error) {
	raw, err := os.ReadFile(filepath.Join(projectPath, "yarn.lock"))
	if err != nil {
		return nil, fmt.Errorf("read yarn.lock: %w", err)
	}
	entries, err := parseYarnLockEntries(string(raw))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("yarn.lock has no dependencies")
	}

	manifest, _ := node.ReadPackageJSONManifest(projectPath)
	rootName := manifest.Name
	if rootName == "" {
		rootName = "root"
	}

	depsGraph := sdk.New()
	rootNode := sdk.NewDependency(sdk.Dependency{Ecosystem: sdk.EcosystemNPM, Name: rootName, Version: manifest.Version, Type: sdk.PackageTypeApplication})
	if err := depsGraph.AddNode(rootNode); err != nil {
		return nil, fmt.Errorf("add yarn root node: %w", err)
	}

	entryNodeByIndex := make(map[int]string, len(entries))
	entriesByName := make(map[string][]int)
	for idx, entry := range entries {
		entriesByName[entry.Name] = append(entriesByName[entry.Name], idx)
	}

	addEntryNode := func(idx int) (string, error) {
		if id, ok := entryNodeByIndex[idx]; ok {
			return id, nil
		}
		entry := entries[idx]
		pkg := sdk.Dependency{
			Ecosystem:   sdk.EcosystemNPM,
			Name:        entry.Name,
			Version:     entry.Version,
			ResolvedURL: entry.Resolved,
			Digests:     node.ParseIntegrityDigests(entry.Integrity),
		}
		pkgNode := sdk.NewDependency(pkg)
		if err := node.AddNodeIfMissing(depsGraph, pkgNode); err != nil {
			return "", err
		}
		entryNodeByIndex[idx] = pkgNode.ID
		return pkgNode.ID, nil
	}

	runtimeDeps := node.MergeStringMaps(manifest.Dependencies, node.MergeStringMaps(manifest.OptionalDependencies, manifest.PeerDependencies))
	directDeps := node.MergeStringMaps(runtimeDeps, manifest.DevDependencies)
	queue := make([]int, 0, len(directDeps))
	seen := make(map[int]struct{})
	for dependencyName, requested := range directDeps {
		entryIdx, ok := selectYarnEntry(entries, entriesByName, dependencyName, requested)
		if !ok {
			continue
		}
		entryID, err := addEntryNode(entryIdx)
		if err != nil {
			return nil, err
		}
		if err := depsGraph.AddEdge(rootNode.ID, entryID); err != nil {
			return nil, fmt.Errorf("add yarn root dependency %q -> %q: %w", rootNode.ID, entryID, err)
		}
		queue = append(queue, entryIdx)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, ok := seen[current]; ok {
			continue
		}
		seen[current] = struct{}{}

		parentID, err := addEntryNode(current)
		if err != nil {
			return nil, err
		}
		for dependencyName, requested := range entries[current].Dependencies {
			entryIdx, ok := selectYarnEntry(entries, entriesByName, dependencyName, requested)
			if ok {
				entryID, err := addEntryNode(entryIdx)
				if err != nil {
					return nil, err
				}
				if err := depsGraph.AddEdge(parentID, entryID); err != nil {
					return nil, fmt.Errorf("add yarn dependency %q -> %q: %w", parentID, entryID, err)
				}
				queue = append(queue, entryIdx)
				continue
			}
			synthetic := sdk.NewDependency(sdk.Dependency{Ecosystem: sdk.EcosystemNPM, Name: dependencyName, Version: node.NormalizeVersionToken(requested)})
			if err := node.AddNodeIfMissing(depsGraph, synthetic); err != nil {
				return nil, err
			}
			if err := depsGraph.AddEdge(parentID, synthetic.ID); err != nil {
				return nil, fmt.Errorf("add yarn synthetic dependency %q -> %q: %w", parentID, synthetic.ID, err)
			}
		}
	}

	node.ApplyDirectDependencyScopes(depsGraph, rootNode.ID, node.DirectDependencyScopes(manifest))
	return depsGraph, nil
}

func parseYarnLockEntries(content string) ([]yarnLockEntry, error) {
	lines := strings.Split(content, "\n")
	entries := make([]yarnLockEntry, 0)
	var current *yarnLockEntry
	inDependencies := false

	flush := func() {
		if current == nil {
			return
		}
		if current.Name != "" && current.Version != "" {
			entries = append(entries, *current)
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Top-level (non-indented) lines ending with ":" are package selectors or block headers.
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			flush()
			selectors := parseYarnSelectors(strings.TrimSuffix(trimmed, ":"))
			if len(selectors) == 0 {
				current = nil
				continue
			}
			name := yarnPackageNameFromSelector(selectors[0])
			// Yarn Berry emits a __metadata stanza that must not become a package node.
			if name == "__metadata" {
				current = nil
				continue
			}
			current = &yarnLockEntry{Name: name, Selectors: selectors, Dependencies: make(map[string]string)}
			inDependencies = false
			continue
		}
		if current == nil {
			continue
		}
		// version field: classic `version "X.Y.Z"`, Berry `version: X.Y.Z`.
		if strings.HasPrefix(trimmed, "version ") || strings.HasPrefix(trimmed, "version: ") {
			raw := trimmed
			if strings.HasPrefix(raw, "version:") {
				raw = strings.TrimPrefix(raw, "version:")
			} else {
				raw = strings.TrimPrefix(raw, "version")
			}
			current.Version = node.NormalizeVersionToken(strings.TrimSpace(raw))
			inDependencies = false
			continue
		}
		// resolved field: classic `resolved "url"`, Berry `resolved: "url"`.
		if strings.HasPrefix(trimmed, "resolved ") || strings.HasPrefix(trimmed, "resolved: ") {
			raw := trimmed
			if strings.HasPrefix(raw, "resolved:") {
				raw = strings.TrimPrefix(raw, "resolved:")
			} else {
				raw = strings.TrimPrefix(raw, "resolved")
			}
			current.Resolved = strings.Trim(strings.TrimSpace(raw), "\"")
			inDependencies = false
			continue
		}
		// integrity field: classic `integrity sha512-...`, Berry `integrity: sha512-...`.
		if strings.HasPrefix(trimmed, "integrity ") || strings.HasPrefix(trimmed, "integrity: ") {
			raw := trimmed
			if strings.HasPrefix(raw, "integrity:") {
				raw = strings.TrimPrefix(raw, "integrity:")
			} else {
				raw = strings.TrimPrefix(raw, "integrity")
			}
			current.Integrity = strings.TrimSpace(raw)
			inDependencies = false
			continue
		}
		if trimmed == "dependencies:" {
			inDependencies = true
			continue
		}
		if inDependencies {
			if strings.HasPrefix(line, "    ") {
				name, req := parseYarnDependencyLine(trimmed)
				name = strings.TrimSuffix(name, ":")
				if name != "" {
					current.Dependencies[name] = req
				}
				continue
			}
			inDependencies = false
		}
	}
	flush()
	return entries, nil
}

func parseYarnSelectors(raw string) []string {
	parts := strings.Split(raw, ",")
	selectors := make([]string, 0, len(parts))
	for _, part := range parts {
		selector := strings.Trim(strings.TrimSpace(part), "\"")
		if selector != "" {
			selectors = append(selectors, selector)
		}
	}
	return selectors
}

func yarnPackageNameFromSelector(selector string) string {
	value := strings.Trim(strings.TrimSpace(selector), "\"")
	if value == "" {
		return ""
	}
	if idx := strings.LastIndex(value, "@npm:"); idx > 0 {
		return value[:idx]
	}
	if idx := strings.LastIndex(value, "@"); idx > 0 {
		return value[:idx]
	}
	return value
}

func parseYarnDependencyLine(line string) (string, string) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", ""
	}
	return strings.Trim(parts[0], "\""), strings.Trim(parts[1], "\"")
}

func selectYarnEntry(entries []yarnLockEntry, entriesByName map[string][]int, dependencyName string, requested string) (int, bool) {
	indices := entriesByName[dependencyName]
	if len(indices) == 0 {
		return 0, false
	}
	normalizedRequest := node.NormalizeVersionToken(requested)
	for _, idx := range indices {
		entry := entries[idx]
		if normalizedRequest != "" && node.NormalizeVersionToken(entry.Version) == normalizedRequest {
			return idx, true
		}
		for _, selector := range entry.Selectors {
			if strings.HasPrefix(selector, dependencyName+"@") && strings.Contains(selector, requested) {
				return idx, true
			}
		}
	}
	return indices[0], true
}
