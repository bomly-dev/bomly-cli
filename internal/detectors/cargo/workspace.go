package cargo

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// cargoModuleGraph identifies one workspace member for manifest-entry
// partitioning: the member directory relative to the workspace root (slash
// form) and its application root node in the resolved graph.
type cargoModuleGraph struct {
	dir    string
	rootID string
}

// cargoLockMember pairs a workspace member directory with its parsed
// Cargo.toml for the no-cargo-binary lock path.
type cargoLockMember struct {
	dir      string
	manifest cargoManifest
}

// parseCargoWorkspaceMembers extracts the members array from a Cargo.toml
// [workspace] section (inline or multiline arrays). Returns nil when the
// manifest declares no workspace.
func parseCargoWorkspaceMembers(text string) []string {
	section := ""
	inMembers := false
	var members []string
	appendQuoted := func(fragment string) {
		for {
			start := strings.IndexByte(fragment, '"')
			if start < 0 {
				return
			}
			rest := fragment[start+1:]
			end := strings.IndexByte(rest, '"')
			if end < 0 {
				return
			}
			if value := strings.TrimSpace(rest[:end]); value != "" {
				members = append(members, value)
			}
			fragment = rest[end+1:]
		}
	}
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && !inMembers {
			section = strings.Trim(line, "[]")
			continue
		}
		if inMembers {
			appendQuoted(line)
			if strings.Contains(line, "]") {
				inMembers = false
			}
			continue
		}
		if section != "workspace" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "members" {
			continue
		}
		value = strings.TrimSpace(value)
		appendQuoted(value)
		if strings.HasPrefix(value, "[") && !strings.Contains(value, "]") {
			inMembers = true
		}
	}
	return members
}

// expandCargoWorkspaceMemberDirs expands member patterns (exact dirs or
// globs like "crates/*") against the workspace root, keeping directories
// that contain a Cargo.toml. Returned paths are root-relative slash paths,
// sorted and deduplicated.
func expandCargoWorkspaceMemberDirs(workingDir string, patterns []string) []string {
	seen := map[string]struct{}{}
	dirs := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(strings.ReplaceAll(pattern, "\\", "/"))
		if pattern == "" {
			continue
		}
		matches, err := filepath.Glob(filepath.Join(workingDir, filepath.FromSlash(pattern)))
		if err != nil {
			continue
		}
		for _, match := range matches {
			exists, err := system.FileExists(filepath.Join(match, "Cargo.toml"))
			if err != nil || !exists {
				continue
			}
			rel, err := filepath.Rel(workingDir, match)
			if err != nil {
				continue
			}
			rel = filepath.ToSlash(rel)
			if rel == "." || strings.HasPrefix(rel, "../") {
				continue
			}
			if _, ok := seen[rel]; ok {
				continue
			}
			seen[rel] = struct{}{}
			dirs = append(dirs, rel)
		}
	}
	sort.Strings(dirs)
	return dirs
}

// cargoDetectionResultFromGraph partitions a resolved workspace graph into
// per-member manifest entries. The workspace root member (dir ".") carries
// the root manifest metadata; a virtual workspace (no root package) emits
// member entries only. Members whose root node was removed by scope
// filtering are skipped.
func cargoDetectionResultFromGraph(g *sdk.Graph, modules []cargoModuleGraph, rootManifest sdk.ManifestMetadata) (sdk.DetectionResult, error) {
	entries := make([]sdk.GraphEntry, 0, len(modules))
	for _, module := range modules {
		if _, ok := g.Node(module.rootID); !ok {
			continue
		}
		moduleGraph, err := detectors.SubgraphFrom(g, module.rootID)
		if err != nil {
			return sdk.DetectionResult{}, fmt.Errorf("extract cargo workspace member graph %q: %w", module.dir, err)
		}
		manifest := sdk.ManifestMetadata{Path: module.dir + "/Cargo.toml", Kind: sdk.ManifestKind("Cargo.toml")}
		if module.dir == "." {
			manifest = rootManifest
		}
		entries = append(entries, sdk.GraphEntry{Graph: moduleGraph, Manifest: manifest})
	}
	if len(entries) == 0 {
		return sdk.DetectionResult{}, fmt.Errorf("cargo workspace produced no member entries")
	}
	return sdk.DetectionResult{Graphs: &sdk.GraphContainer{Entries: entries}}, nil
}

// depGraphFromLockWorkspace builds a workspace graph from Cargo.lock plus the
// parsed member manifests, without invoking the cargo binary. Workspace
// members become application root nodes; member manifest dependency lists
// annotate direct-edge scopes exactly like the single-package lock path does
// for its root.
func depGraphFromLockWorkspace(lockRaw []byte, rootManifest cargoManifest, members []cargoLockMember, scopeFilter sdk.Scope) (*sdk.Graph, []cargoModuleGraph, string, error) {
	packages := parseCargoLockPackages(string(lockRaw))
	if len(packages) == 0 {
		return nil, nil, "", fmt.Errorf("cargo.lock does not contain any packages")
	}
	byName := make(map[string]lockPackage, len(packages))
	for _, pkg := range packages {
		byName[pkg.Name] = pkg
	}
	applicationNames := map[string]struct{}{}
	if rootManifest.Name != "" {
		applicationNames[rootManifest.Name] = struct{}{}
	}
	for _, member := range members {
		if member.manifest.Name != "" {
			applicationNames[member.manifest.Name] = struct{}{}
		}
	}

	g := sdk.New()
	nodeFor := func(name, version string, application bool) *sdk.Dependency {
		pkgType := "crate"
		if application {
			pkgType = "application"
		}
		return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemRust,
			Name:           name,
			Version:        version,
			PackageManager: sdk.PackageManagerCargo,
			Type:           sdk.ParsePackageType(pkgType),
			Language:       "rust",
			PURL:           sdk.BuildPackageURL("cargo", "", name, version)},
		})
	}
	lockVersion := func(manifest cargoManifest) string {
		if pkg, ok := byName[manifest.Name]; ok && pkg.Version != "" {
			return pkg.Version
		}
		return manifest.Version
	}

	rootID := ""
	if rootManifest.Name != "" {
		root := nodeFor(rootManifest.Name, lockVersion(rootManifest), true)
		if err := addNodeIfMissing(g, root); err != nil {
			return nil, nil, "", err
		}
		rootID = root.ID
	}
	modules := make([]cargoModuleGraph, 0, len(members))
	memberIDs := map[string]string{}
	for _, member := range members {
		if member.manifest.Name == "" {
			continue
		}
		memberNode := nodeFor(member.manifest.Name, lockVersion(member.manifest), true)
		if err := addNodeIfMissing(g, memberNode); err != nil {
			return nil, nil, "", err
		}
		memberIDs[member.manifest.Name] = memberNode.ID
		modules = append(modules, cargoModuleGraph{dir: member.dir, rootID: memberNode.ID})
	}
	for _, pkg := range packages {
		if _, ok := applicationNames[pkg.Name]; ok {
			continue
		}
		if err := addNodeIfMissing(g, nodeFor(pkg.Name, pkg.Version, false)); err != nil {
			return nil, nil, "", err
		}
	}

	idFor := func(name string) (string, bool) {
		if id, ok := memberIDs[name]; ok {
			return id, true
		}
		if rootManifest.Name != "" && name == rootManifest.Name && rootID != "" {
			return rootID, true
		}
		pkg, ok := byName[name]
		if !ok {
			return "", false
		}
		return nodeFor(pkg.Name, pkg.Version, false).ID, true
	}

	// Transitive edges from the lockfile for non-application packages.
	for _, pkg := range packages {
		if _, ok := applicationNames[pkg.Name]; ok {
			continue
		}
		parentID, ok := idFor(pkg.Name)
		if !ok {
			continue
		}
		for _, depName := range pkg.Dependencies {
			childID, ok := idFor(depName)
			if !ok || childID == rootID {
				continue
			}
			if err := g.AddEdge(parentID, childID); err != nil {
				return nil, nil, "", fmt.Errorf("add Cargo.lock dependency %q -> %q: %w", parentID, childID, err)
			}
		}
	}

	// Direct edges + scopes for application roots from their manifests.
	applyManifestEdges := func(parentID string, manifest cargoManifest) error {
		addDirect := func(names []string, scope sdk.Scope) error {
			for _, depName := range names {
				childID, ok := idFor(depName)
				if !ok || childID == parentID {
					continue
				}
				if existing, ok := g.Node(childID); ok {
					existing.AddScope(scope)
				}
				if err := g.AddEdge(parentID, childID); err != nil {
					return fmt.Errorf("add Cargo direct dependency %q -> %q: %w", parentID, childID, err)
				}
			}
			return nil
		}
		if err := addDirect(manifest.Dependencies, sdk.ScopeRuntime); err != nil {
			return err
		}
		return addDirect(manifest.DevDependencies, sdk.ScopeDevelopment)
	}
	if rootID != "" {
		if err := applyManifestEdges(rootID, rootManifest); err != nil {
			return nil, nil, "", err
		}
	}
	for _, member := range members {
		memberID, ok := memberIDs[member.manifest.Name]
		if !ok {
			continue
		}
		if err := applyManifestEdges(memberID, member.manifest); err != nil {
			return nil, nil, "", err
		}
	}

	propagateScopesFromApplicationRoots(g)
	filtered, err := sdk.FilterGraphByScope(g, scopeFilter)
	if err != nil {
		return nil, nil, "", err
	}
	return filtered, modules, rootID, nil
}

// readCargoLockMembers parses each member directory's Cargo.toml, skipping
// unreadable or package-less members.
func readCargoLockMembers(workingDir string, memberDirs []string) []cargoLockMember {
	members := make([]cargoLockMember, 0, len(memberDirs))
	for _, dir := range memberDirs {
		raw, err := os.ReadFile(filepath.Join(workingDir, filepath.FromSlash(dir), "Cargo.toml"))
		if err != nil {
			continue
		}
		manifest := parseCargoManifest(string(raw))
		if manifest.Name == "" {
			continue
		}
		members = append(members, cargoLockMember{dir: dir, manifest: manifest})
	}
	return members
}
