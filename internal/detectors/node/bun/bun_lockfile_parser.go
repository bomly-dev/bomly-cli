package bun

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/sdk"
)

type bunLockfile struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Workspaces      map[string]bunWorkspace    `json:"workspaces"`
	Packages        map[string]json.RawMessage `json:"packages"`
}

type bunWorkspace struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type bunPackageMetadata struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type bunPackageEntry struct {
	key       string
	name      string
	version   string
	resolved  string
	integrity string
	metadata  bunPackageMetadata
	source    sdk.DependencySource
	nodeID    string
}

type bunModuleGraph struct{ dir, rootID string }

type bunLockfileGraphs struct {
	graph   *sdk.Graph
	rootID  string
	modules []bunModuleGraph
}

func depGraphFromBunLockfile(projectPath string) (bunLockfileGraphs, error) {
	raw, err := os.ReadFile(filepath.Join(projectPath, "bun.lock"))
	if err != nil {
		return bunLockfileGraphs{}, fmt.Errorf("read bun.lock: %w", err)
	}
	clean, err := normalizeJSONC(node.StripUTF8BOM(raw))
	if err != nil {
		return bunLockfileGraphs{}, fmt.Errorf("normalize bun.lock JSONC: %w", err)
	}
	var lockfile bunLockfile
	if err := json.Unmarshal(clean, &lockfile); err != nil {
		return bunLockfileGraphs{}, fmt.Errorf("parse bun.lock: %w", err)
	}
	if lockfile.LockfileVersion != 0 && lockfile.LockfileVersion != 1 {
		return bunLockfileGraphs{}, fmt.Errorf("unsupported bun lockfileVersion %d (supported: 0 and 1)", lockfile.LockfileVersion)
	}
	if len(lockfile.Packages) == 0 {
		return bunLockfileGraphs{}, errors.New("bun.lock has no packages")
	}

	rootWorkspace := lockfile.Workspaces[""]
	if rootWorkspace.Name == "" {
		manifest, _ := node.ReadPackageJSONManifest(projectPath)
		rootWorkspace = bunWorkspace{
			Name: manifest.Name, Version: manifest.Version,
			Dependencies: manifest.Dependencies, DevDependencies: manifest.DevDependencies,
			OptionalDependencies: manifest.OptionalDependencies, PeerDependencies: manifest.PeerDependencies,
		}
		if rootWorkspace.Name == "" {
			rootWorkspace.Name = "root"
		}
	}
	graph := sdk.New()
	root := bunApplicationNode(rootWorkspace.Name, rootWorkspace.Version, sdk.DependencySourceProject, "")
	if err := graph.AddNode(root); err != nil {
		return bunLockfileGraphs{}, fmt.Errorf("add Bun root node: %w", err)
	}

	workspaceByDir := map[string]string{"": root.ID, ".": root.ID}
	workspaceByName := map[string]string{rootWorkspace.Name: root.ID}
	modules := make([]bunModuleGraph, 0, len(lockfile.Workspaces))
	workspaceDirs := sortedWorkspaceKeys(lockfile.Workspaces)
	for _, dir := range workspaceDirs {
		if dir == "" || dir == "." {
			continue
		}
		workspace := lockfile.Workspaces[dir]
		cleanDir := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(dir)), "./")
		name := workspace.Name
		if name == "" {
			name = filepath.Base(cleanDir)
		}
		member := bunApplicationNode(name, workspace.Version, sdk.DependencySourceWorkspace, "workspace:"+cleanDir)
		if err := node.AddNodeIfMissing(graph, member); err != nil {
			return bunLockfileGraphs{}, err
		}
		workspaceByDir[cleanDir], workspaceByName[name] = member.ID, member.ID
		modules = append(modules, bunModuleGraph{dir: cleanDir, rootID: member.ID})
	}

	entries := make([]bunPackageEntry, 0, len(lockfile.Packages))
	byKey := make(map[string]int, len(lockfile.Packages))
	byName := make(map[string][]int)
	packageKeys := make([]string, 0, len(lockfile.Packages))
	for key := range lockfile.Packages {
		packageKeys = append(packageKeys, key)
	}
	sort.Strings(packageKeys)
	for _, key := range packageKeys {
		entry, err := parseBunPackageEntry(key, lockfile.Packages[key])
		if err != nil {
			return bunLockfileGraphs{}, err
		}
		dep := sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, PackageManager: sdk.PackageManagerBun, Name: entry.name, Version: entry.version}, Source: entry.source, ResolvedURL: entry.resolved, Digests: node.ParseIntegrityDigests(entry.integrity)}
		pkgNode := sdk.NewDependency(dep)
		if _, exists := graph.Node(pkgNode.ID); exists {
			pkgNode = sdk.NewDependencyWithID("bun-package:"+key, dep)
		}
		if err := node.AddNodeIfMissing(graph, pkgNode); err != nil {
			return bunLockfileGraphs{}, err
		}
		entry.nodeID = pkgNode.ID
		idx := len(entries)
		entries = append(entries, entry)
		byKey[key] = idx
		byName[entry.name] = append(byName[entry.name], idx)
	}

	for idx := range entries {
		entry := entries[idx]
		children := mergeBunDependencyMaps(entry.metadata.Dependencies, entry.metadata.OptionalDependencies, entry.metadata.DevDependencies)
		for dependencyName, requested := range children {
			targetID, ok := resolveBunDependency(entries, byKey, byName, workspaceByName, dependencyName, requested)
			if !ok {
				target, err := addSyntheticBunDependency(graph, dependencyName, requested)
				if err != nil {
					return bunLockfileGraphs{}, err
				}
				targetID = target
			}
			if targetID != entry.nodeID {
				if err := graph.AddEdge(entry.nodeID, targetID); err != nil {
					return bunLockfileGraphs{}, fmt.Errorf("add Bun dependency %q -> %q: %w", entry.nodeID, targetID, err)
				}
			}
		}
	}

	for _, dir := range workspaceDirs {
		workspace := lockfile.Workspaces[dir]
		cleanDir := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(dir)), "./")
		if dir == "" || dir == "." {
			cleanDir = ""
		}
		parentID := workspaceByDir[cleanDir]
		deps := mergeBunDependencyMaps(workspace.Dependencies, workspace.OptionalDependencies, workspace.PeerDependencies, workspace.DevDependencies)
		for dependencyName, requested := range deps {
			targetID, ok := resolveBunDependency(entries, byKey, byName, workspaceByName, dependencyName, requested)
			if !ok {
				targetID, err = addSyntheticBunDependency(graph, dependencyName, requested)
				if err != nil {
					return bunLockfileGraphs{}, err
				}
			}
			if parentID != "" && parentID != targetID {
				if err := graph.AddEdge(parentID, targetID); err != nil {
					return bunLockfileGraphs{}, fmt.Errorf("add Bun workspace dependency %q -> %q: %w", parentID, targetID, err)
				}
			}
		}
		node.ApplyDirectDependencyScopes(graph, parentID, bunWorkspaceScopes(workspace))
	}

	return bunLockfileGraphs{graph: graph, rootID: root.ID, modules: modules}, nil
}

func parseBunPackageEntry(key string, raw json.RawMessage) (bunPackageEntry, error) {
	var tuple []json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil {
		return bunPackageEntry{}, fmt.Errorf("parse Bun package %q tuple: %w", key, err)
	}
	if len(tuple) == 0 {
		return bunPackageEntry{}, fmt.Errorf("parse Bun package %q: empty tuple", key)
	}
	var identity string
	if err := json.Unmarshal(tuple[0], &identity); err != nil {
		return bunPackageEntry{}, fmt.Errorf("parse Bun package %q identity: %w", key, err)
	}
	name, version := splitBunIdentity(identity)
	if name == "" {
		return bunPackageEntry{}, fmt.Errorf("parse Bun package %q: invalid identity %q", key, identity)
	}
	entry := bunPackageEntry{key: key, name: name, version: version, source: node.DependencySourceFromSpecifier(version)}
	if len(tuple) > 1 {
		_ = json.Unmarshal(tuple[1], &entry.resolved)
	}
	if len(tuple) > 2 {
		_ = json.Unmarshal(tuple[2], &entry.metadata)
	}
	if len(tuple) > 3 {
		_ = json.Unmarshal(tuple[3], &entry.integrity)
	}
	return entry, nil
}

func splitBunIdentity(value string) (string, string) {
	value = strings.TrimSpace(value)
	idx := strings.LastIndex(value, "@")
	if idx <= 0 || idx == len(value)-1 {
		return value, ""
	}
	return value[:idx], node.NormalizeVersionToken(value[idx+1:])
}

func bunApplicationNode(name, version string, source sdk.DependencySource, forcedID string) *sdk.Dependency {
	dep := sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, PackageManager: sdk.PackageManagerBun, Name: name, Version: version, Type: sdk.PackageTypeApplication}, Source: source}
	if forcedID != "" {
		return sdk.NewDependencyWithID(forcedID, dep)
	}
	return sdk.NewDependency(dep)
}

func resolveBunDependency(entries []bunPackageEntry, byKey map[string]int, byName map[string][]int, workspaces map[string]string, name, requested string) (string, bool) {
	if source := node.DependencySourceFromSpecifier(requested); source == sdk.DependencySourceWorkspace {
		id, ok := workspaces[name]
		return id, ok
	} else if source != sdk.DependencySourceRegistry {
		return "", false
	}
	actualName, actualRequest := bunAliasTarget(name, requested)
	if idx, ok := byKey[name]; ok {
		candidate := entries[idx]
		if candidate.name != name || bunVersionMatches(candidate.version, actualRequest) {
			return candidate.nodeID, true
		}
	}
	indices := byName[actualName]
	if len(indices) == 0 {
		return "", false
	}
	normalized := node.NormalizeVersionToken(actualRequest)
	for _, idx := range indices {
		if entries[idx].version == normalized {
			return entries[idx].nodeID, true
		}
	}
	if constraint, err := semver.NewConstraint(strings.TrimPrefix(strings.TrimSpace(actualRequest), "npm:")); err == nil {
		for _, idx := range indices {
			if version, versionErr := semver.NewVersion(entries[idx].version); versionErr == nil && constraint.Check(version) {
				return entries[idx].nodeID, true
			}
		}
	}
	if len(indices) == 1 {
		return entries[indices[0]].nodeID, true
	}
	return "", false
}

func bunVersionMatches(version, requested string) bool {
	if version == node.NormalizeVersionToken(requested) {
		return true
	}
	constraint, err := semver.NewConstraint(strings.TrimPrefix(strings.TrimSpace(requested), "npm:"))
	if err != nil {
		return false
	}
	parsed, err := semver.NewVersion(version)
	return err == nil && constraint.Check(parsed)
}

func bunAliasTarget(name, requested string) (string, string) {
	value := strings.TrimSpace(requested)
	if !strings.HasPrefix(value, "npm:") {
		return name, value
	}
	return splitBunIdentity(strings.TrimPrefix(value, "npm:"))
}

func addSyntheticBunDependency(graph *sdk.Graph, name, requested string) (string, error) {
	actualName, version := bunAliasTarget(name, requested)
	dep := sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, PackageManager: sdk.PackageManagerBun, Name: actualName, Version: node.NormalizeVersionToken(version)}, Source: node.DependencySourceFromSpecifier(requested)}
	synthetic := sdk.NewDependency(dep)
	if err := node.AddNodeIfMissing(graph, synthetic); err != nil {
		return "", err
	}
	return synthetic.ID, nil
}

func mergeBunDependencyMaps(maps ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, values := range maps {
		for name, version := range values {
			out[name] = version
		}
	}
	return out
}

func bunWorkspaceScopes(workspace bunWorkspace) map[string]sdk.Scope {
	out := make(map[string]sdk.Scope)
	for name := range mergeBunDependencyMaps(workspace.Dependencies, workspace.OptionalDependencies, workspace.PeerDependencies) {
		out[name] = sdk.ScopeRuntime
	}
	for name := range workspace.DevDependencies {
		if _, runtime := out[name]; !runtime {
			out[name] = sdk.ScopeDevelopment
		}
	}
	return out
}

func sortedWorkspaceKeys(workspaces map[string]bunWorkspace) []string {
	keys := make([]string, 0, len(workspaces))
	for key := range workspaces {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
