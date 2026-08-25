package cargo

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
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
		moduleGraph, err := detectorkit.SubgraphFrom(g, module.rootID)
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

	g := sdk.New()
	nodeFor := func(pkg lockPackage, application bool) *sdk.Dependency {
		pkgType := "crate"
		source := cargoDependencySource(pkg.Source)
		if application {
			pkgType = "application"
			source = sdk.DependencySourceWorkspace
		}
		node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemRust,
			Name:           pkg.Name,
			Version:        pkg.Version,
			PackageManager: sdk.PackageManagerCargo,
			Type:           sdk.ParsePackageType(pkgType),
			Language:       "rust",
			PURL:           sdk.BuildPackageURL("cargo", "", pkg.Name, pkg.Version)}, Source: source, ResolvedURL: pkg.Source,
		})
		if !application {
			// A workspace member is the project's own code. It has no external
			// origin, and a lock entry that merely shares its name -- an
			// unrelated crate from a git remote -- must not be credited to it.
			setCargoOrigin(node, pkg.Source)
		}
		return node
	}
	// Each application root claims its own lock record -- matched by name,
	// declared version, and the absence of a source (isProjectLockRecord) --
	// rather than by name alone, which credited a member with an unrelated
	// same-named crate's version and source and dropped that crate from the
	// graph entirely (issue #399). Only the claimed records are withheld from
	// the ordinary dependency pass below; a same-named external crate keeps
	// its own node.
	type applicationRoot struct {
		manifest cargoManifest
		record   lockPackage
		id       string
	}
	claimed := map[string]struct{}{}
	applicationRefs := map[string]string{}
	roots := make([]applicationRoot, 0, len(members)+1)
	addRoot := func(manifest cargoManifest) (string, error) {
		record := projectLockRecord(packages, manifest)
		node := nodeFor(record, true)
		if err := addNodeIfMissing(g, node); err != nil {
			return "", err
		}
		claimed[qualifiedLockKey(record)] = struct{}{}
		// Other lock records reference a member as "name" or "name version";
		// first-wins keeps resolution deterministic in declaration order.
		for _, ref := range []string{record.Name, strings.TrimSpace(record.Name + " " + record.Version)} {
			if _, taken := applicationRefs[ref]; !taken {
				applicationRefs[ref] = node.ID
			}
		}
		roots = append(roots, applicationRoot{manifest: manifest, record: record, id: node.ID})
		return node.ID, nil
	}

	rootID := ""
	if rootManifest.Name != "" {
		id, err := addRoot(rootManifest)
		if err != nil {
			return nil, nil, "", err
		}
		rootID = id
	}
	modules := make([]cargoModuleGraph, 0, len(members))
	for _, member := range members {
		if member.manifest.Name == "" {
			continue
		}
		id, err := addRoot(member.manifest)
		if err != nil {
			return nil, nil, "", err
		}
		modules = append(modules, cargoModuleGraph{dir: member.dir, rootID: id})
	}
	index := &lockIndex{nodeID: make(map[string]string, len(packages)*3)}
	for _, pkg := range packages {
		if _, ok := claimed[qualifiedLockKey(pkg)]; ok {
			continue
		}
		node := nodeFor(pkg, false)
		surviving, err := detectors.EnsureOccurrence(g, node, strings.TrimSpace(pkg.Source))
		if err != nil {
			return nil, nil, "", err
		}
		index.record(pkg, surviving.ID)
	}

	idFor := func(ref string) (string, bool) {
		ref = strings.TrimSpace(ref)
		if id, ok := applicationRefs[ref]; ok {
			return id, true
		}
		return index.resolve(ref)
	}

	// Transitive edges from the lockfile for non-application packages.
	for _, pkg := range packages {
		if _, ok := claimed[qualifiedLockKey(pkg)]; ok {
			continue
		}
		parentID, ok := index.resolve(qualifiedLockKey(pkg))
		if !ok {
			continue
		}
		for _, depRef := range pkg.Dependencies {
			childID, ok := idFor(depRef)
			if !ok || childID == rootID {
				continue
			}
			if err := g.AddEdge(parentID, childID); err != nil {
				return nil, nil, "", fmt.Errorf("add Cargo.lock dependency %q -> %q: %w", parentID, childID, err)
			}
		}
	}

	// Direct edges + scopes for application roots from their manifests. A
	// root's own lock record names each dependency at whatever precision
	// disambiguates it; prefer that over the manifest's bare name.
	applyManifestEdges := func(root applicationRoot) error {
		refs := lockDependencyRefs(root.record)
		addDirect := func(names []string, scope sdk.Scope) error {
			for _, depName := range names {
				ref := depName
				if qualified, ok := refs[depName]; ok {
					ref = qualified
				}
				childID, ok := idFor(ref)
				if !ok && ref != depName {
					childID, ok = idFor(depName)
				}
				if !ok || childID == root.id {
					continue
				}
				if existing, ok := g.Node(childID); ok {
					existing.AddScope(scope)
				}
				if err := g.AddEdge(root.id, childID); err != nil {
					return fmt.Errorf("add Cargo direct dependency %q -> %q: %w", root.id, childID, err)
				}
			}
			return nil
		}
		if err := addDirect(root.manifest.Dependencies, sdk.ScopeRuntime); err != nil {
			return err
		}
		return addDirect(root.manifest.DevDependencies, sdk.ScopeDevelopment)
	}
	for _, root := range roots {
		if err := applyManifestEdges(root); err != nil {
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
		raw, err := system.ReadRepositoryFile(filepath.Join(workingDir, filepath.FromSlash(dir), "Cargo.toml"))
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
