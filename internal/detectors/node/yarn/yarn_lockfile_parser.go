package yarn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/sdk"
)

type yarnLockEntry struct {
	Name         string
	Version      string
	Resolved     string
	Resolution   string
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
	rootNode := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: rootName, Version: manifest.Version, Type: sdk.PackageTypeApplication}, Source: sdk.DependencySourceProject})
	if err := depsGraph.AddNode(rootNode); err != nil {
		return nil, fmt.Errorf("add yarn root node: %w", err)
	}

	entryNodeByIndex := make(map[int]string, len(entries))
	entriesByName := make(map[string][]int)
	for idx, entry := range entries {
		entriesByName[entry.Name] = append(entriesByName[entry.Name], idx)
		for _, selector := range entry.Selectors {
			selectorName := yarnPackageNameFromSelector(selector)
			if selectorName != "" && selectorName != entry.Name {
				entriesByName[selectorName] = append(entriesByName[selectorName], idx)
			}
		}
	}

	addEntryNode := func(idx int) (string, error) {
		if id, ok := entryNodeByIndex[idx]; ok {
			return id, nil
		}
		entry := entries[idx]
		pkg := sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM,
			Name:    entry.Name,
			Version: entry.Version}, Source: yarnEntrySource(entry), ResolvedURL: entry.Resolved,
			Digests: node.ParseIntegrityDigests(entry.Integrity),
		}
		pkgNode := sdk.NewDependency(pkg)
		if existing, ok := depsGraph.Node(pkgNode.ID); ok && existing.Type == sdk.PackageTypeApplication {
			pkgNode = sdk.NewDependencyWithID(fmt.Sprintf("yarn-package:%d", idx), pkg)
		}
		if err := node.AddNodeIfMissing(depsGraph, pkgNode); err != nil {
			return "", err
		}
		entryNodeByIndex[idx] = pkgNode.ID
		return pkgNode.ID, nil
	}

	// Inventory every resolved entry first. Edges and manifest roots are wired
	// in subsequent passes so lockfile components without a known parent remain
	// available for unknown-relationship attachment.
	for idx := range entries {
		if _, err := addEntryNode(idx); err != nil {
			return nil, err
		}
	}
	for current := range entries {
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
				if parentID == entryID {
					continue
				}
				if err := depsGraph.AddEdge(parentID, entryID); err != nil {
					return nil, fmt.Errorf("add yarn dependency %q -> %q: %w", parentID, entryID, err)
				}
				continue
			}
			synthetic := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: dependencyName, Version: node.NormalizeVersionToken(requested)}, Source: node.DependencySourceFromSpecifier(requested)})
			if err := node.AddNodeIfMissing(depsGraph, synthetic); err != nil {
				return nil, err
			}
			if err := depsGraph.AddEdge(parentID, synthetic.ID); err != nil {
				return nil, fmt.Errorf("add yarn synthetic dependency %q -> %q: %w", parentID, synthetic.ID, err)
			}
		}
	}

	runtimeDeps := node.MergeStringMaps(manifest.Dependencies, node.MergeStringMaps(manifest.OptionalDependencies, manifest.PeerDependencies))
	directDeps := node.MergeStringMaps(runtimeDeps, manifest.DevDependencies)
	for dependencyName, requested := range directDeps {
		entryIdx, ok := selectYarnEntry(entries, entriesByName, dependencyName, requested)
		if !ok {
			synthetic := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: dependencyName, Version: node.NormalizeVersionToken(requested)}, Source: node.DependencySourceFromSpecifier(requested)})
			if err := node.AddNodeIfMissing(depsGraph, synthetic); err != nil {
				return nil, err
			}
			if rootNode.ID != synthetic.ID {
				if err := depsGraph.AddEdge(rootNode.ID, synthetic.ID); err != nil {
					return nil, fmt.Errorf("add yarn root dependency %q -> %q: %w", rootNode.ID, synthetic.ID, err)
				}
			}
			continue
		}
		entryID, err := addEntryNode(entryIdx)
		if err != nil {
			return nil, err
		}
		if rootNode.ID == entryID {
			continue
		}
		if err := depsGraph.AddEdge(rootNode.ID, entryID); err != nil {
			return nil, fmt.Errorf("add yarn root dependency %q -> %q: %w", rootNode.ID, entryID, err)
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
		if strings.HasPrefix(trimmed, "resolution: ") {
			current.Resolution = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "resolution:")), "\"")
			if name := yarnPackageNameFromResolution(current.Resolution); name != "" {
				current.Name = name
			}
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
		if trimmed == "dependencies:" || trimmed == "optionalDependencies:" {
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
	parts := splitYarnOutsideQuotes(raw, ',')
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
	line = strings.TrimSpace(line)
	if key, value, ok := splitYarnMapping(line); ok {
		return strings.Trim(strings.TrimSpace(key), "\"'"), strings.Trim(strings.TrimSpace(value), "\"'")
	}
	key, value, ok := splitYarnWhitespaceMapping(line)
	if !ok {
		return "", ""
	}
	return strings.Trim(strings.TrimSpace(key), "\"'"), strings.Trim(strings.TrimSpace(value), "\"'")
}

func selectYarnEntry(entries []yarnLockEntry, entriesByName map[string][]int, dependencyName string, requested string) (int, bool) {
	indices := entriesByName[dependencyName]
	if len(indices) == 0 {
		return 0, false
	}
	normalizedRequest := normalizeYarnRange(requested)
	// Prefer the descriptor group Yarn recorded for the exact requested range.
	// A merely compatible version can occur earlier in the lockfile and must not
	// shadow that authoritative selector.
	for _, idx := range indices {
		entry := entries[idx]
		if normalizedRequest != "" && node.NormalizeVersionToken(entry.Version) == normalizedRequest {
			return idx, true
		}
		for _, selector := range entry.Selectors {
			if strings.HasPrefix(selector, dependencyName+"@") && normalizeYarnRange(strings.TrimPrefix(selector, dependencyName+"@")) == normalizedRequest {
				return idx, true
			}
		}
	}
	for _, idx := range indices {
		entry := entries[idx]
		if constraint, err := semver.NewConstraint(normalizedRequest); err == nil {
			if version, err := semver.NewVersion(entry.Version); err == nil && constraint.Check(version) {
				return idx, true
			}
		}
	}
	if len(indices) == 1 {
		return indices[0], true
	}
	return 0, false
}

func splitYarnWhitespaceMapping(value string) (string, string, bool) {
	var quote rune
	for idx, char := range value {
		switch {
		case quote != 0 && char == quote:
			quote = 0
		case quote == 0 && (char == '\'' || char == '"'):
			quote = char
		case quote == 0 && unicode.IsSpace(char):
			key := strings.TrimSpace(value[:idx])
			remainder := strings.TrimSpace(value[idx:])
			return key, remainder, key != "" && remainder != ""
		}
	}
	return "", "", false
}

func normalizeYarnRange(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "\"'")
	value = strings.TrimPrefix(value, "npm:")
	return value
}

func splitYarnOutsideQuotes(value string, separator rune) []string {
	var out []string
	start := 0
	var quote rune
	for idx, char := range value {
		switch {
		case quote != 0 && char == quote:
			quote = 0
		case quote == 0 && (char == '\'' || char == '"'):
			quote = char
		case quote == 0 && char == separator:
			out = append(out, value[start:idx])
			start = idx + len(string(char))
		}
	}
	out = append(out, value[start:])
	return out
}

func splitYarnMapping(value string) (string, string, bool) {
	var quote rune
	for idx, char := range value {
		switch {
		case quote != 0 && char == quote:
			quote = 0
		case quote == 0 && (char == '\'' || char == '"'):
			quote = char
		case quote == 0 && char == ':':
			return value[:idx], value[idx+1:], true
		}
	}
	return "", "", false
}

func yarnPackageNameFromResolution(resolution string) string {
	value := strings.Trim(strings.TrimSpace(resolution), "\"'")
	if strings.HasPrefix(value, "virtual:") {
		if idx := strings.Index(value, "#"); idx >= 0 {
			value = value[idx+1:]
		}
	}
	value = strings.TrimPrefix(value, "patch:")
	return yarnPackageNameFromSelector(value)
}

func yarnEntrySource(entry yarnLockEntry) sdk.DependencySource {
	for _, value := range append(append([]string(nil), entry.Selectors...), entry.Resolution) {
		lower := strings.ToLower(value)
		for _, marker := range []string{"workspace:", "link:", "file:", "git:", "git+", "github:", "http:", "https:"} {
			if idx := strings.Index(lower, marker); idx >= 0 {
				return node.DependencySourceFromSpecifier(value[idx:])
			}
		}
	}
	return sdk.DependencySourceRegistry
}
