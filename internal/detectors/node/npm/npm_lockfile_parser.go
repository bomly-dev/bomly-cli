package npm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/sdk"
)

type npmPackageLock struct {
	Name            string                       `json:"name"`
	Version         string                       `json:"version"`
	LockfileVersion int                          `json:"lockfileVersion"`
	Dependencies    map[string]*node.NPMListNode `json:"dependencies"`
	Packages        map[string]npmLockPackage    `json:"packages"`
}

type npmLockPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Resolved is the registry URL for fetched packages; for link entries it
	// is the local directory the link points at (a workspace member dir).
	Resolved string `json:"resolved"`
	// Link marks a node_modules alias entry pointing at a local directory
	// (npm writes one per workspace member).
	Link                     bool              `json:"link"`
	Integrity                string            `json:"integrity"`
	License                  string            `json:"license"`
	Dependencies             map[string]string `json:"dependencies"`
	DevDependencies          map[string]string `json:"devDependencies"`
	OptionalDependencies     map[string]string `json:"optionalDependencies"`
	PeerDependencies         map[string]string `json:"peerDependencies"`
	OptionalPeerDependencies []string          `json:"optionalPeerDependencies"`
	Engines                  npmEngines        `json:"engines"`
	Bundled                  bool              `json:"bundled"`
	Extraneous               bool              `json:"extraneous"`
	HasInstallScript         bool              `json:"hasInstallScript"`
	Dev                      bool              `json:"dev"`
	Optional                 bool              `json:"optional"`
}

type npmEngines map[string]string

func (e *npmEngines) UnmarshalJSON(raw []byte) error {
	var engines map[string]string
	if err := json.Unmarshal(raw, &engines); err == nil {
		*e = engines
		return nil
	}

	// Some historical npm packages encode `engines` as an array such as
	// ["node", "rhino"]. That shape does not carry version constraints, so
	// keep parsing and omit engine metadata for that package.
	var ignored []any
	if err := json.Unmarshal(raw, &ignored); err == nil {
		*e = nil
		return nil
	}
	var ignoredString string
	if err := json.Unmarshal(raw, &ignoredString); err == nil {
		*e = nil
		return nil
	}
	return fmt.Errorf("parse engines field")
}

// npmLockPackageMetadata builds an NPMPackageMetadata from a lockfile package entry.
// Returns nil when there is no ecosystem-specific metadata worth recording.
func npmLockPackageMetadata(entry npmLockPackage) *sdk.NPMPackageMetadata {
	if !entry.Bundled && !entry.Extraneous && !entry.HasInstallScript &&
		len(entry.PeerDependencies) == 0 && len(entry.OptionalPeerDependencies) == 0 &&
		len(entry.Engines) == 0 {
		return nil
	}
	meta := &sdk.NPMPackageMetadata{
		Bundled:                  entry.Bundled,
		Extraneous:               entry.Extraneous,
		HasInstallScript:         entry.HasInstallScript,
		OptionalPeerDependencies: entry.OptionalPeerDependencies,
	}
	if len(entry.PeerDependencies) > 0 {
		meta.PeerDependencies = entry.PeerDependencies
	}
	if len(entry.Engines) > 0 {
		meta.Engines = entry.Engines
	}
	return meta
}

// npmModuleGraph identifies one workspace member inside the parsed lockfile
// graph: the member's directory (relative to the project root, slash form)
// and its application root node in the merged graph.
type npmModuleGraph struct {
	dir    string
	rootID string
}

// npmLockfileGraphs carries the merged lockfile graph plus the workspace
// member roots the detector partitions into per-module manifest entries.
type npmLockfileGraphs struct {
	graph   *sdk.Graph
	rootID  string
	modules []npmModuleGraph
}

func depGraphFromNPMLockfile(projectPath string) (npmLockfileGraphs, error) {
	raw, err := os.ReadFile(filepath.Join(projectPath, "package-lock.json"))
	if err != nil {
		return npmLockfileGraphs{}, fmt.Errorf("read package-lock.json: %w", err)
	}

	var lockfile npmPackageLock
	if err := json.Unmarshal(raw, &lockfile); err != nil {
		return npmLockfileGraphs{}, fmt.Errorf("parse package-lock.json: %w", err)
	}

	// Prefer the packages-map path (v2/v3) when available: it carries richer metadata
	// (resolved URL, integrity, license, engines). Fall back to the flat dependencies path
	// only for v1 lockfiles that have no packages map.
	if len(lockfile.Packages) == 0 {
		if len(lockfile.Dependencies) == 0 {
			return npmLockfileGraphs{}, errors.New("package-lock.json has no dependencies")
		}
		root := &node.NPMListNode{Name: lockfile.Name, Version: lockfile.Version, Dependencies: lockfile.Dependencies}
		if root.Name == "" {
			root.Name = "root"
		}
		flat, err := node.DepGraphFromNPMNode(root)
		if err != nil {
			return npmLockfileGraphs{}, err
		}
		roots := flat.Roots()
		rootID := ""
		if len(roots) > 0 && roots[0] != nil {
			rootID = roots[0].ID
		}
		return npmLockfileGraphs{graph: flat, rootID: rootID}, nil
	}

	depsGraph := sdk.New()
	rootName := lockfile.Name
	if rootName == "" {
		rootName = "root"
	}
	rootNode := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: rootName, Version: lockfile.Version, Type: sdk.PackageTypeApplication}})
	if err := depsGraph.AddNode(rootNode); err != nil {
		return npmLockfileGraphs{}, fmt.Errorf("add npm root node: %w", err)
	}

	paths := make([]string, 0, len(lockfile.Packages))
	for packagePath := range lockfile.Packages {
		paths = append(paths, packagePath)
	}
	sort.Strings(paths)

	pathToID := map[string]string{"": rootNode.ID}
	modules := make([]npmModuleGraph, 0)
	for _, packagePath := range paths {
		if packagePath == "" {
			continue
		}
		entry := lockfile.Packages[packagePath]
		if entry.Link {
			// node_modules alias to a local directory (workspace member):
			// resolved after all real entries have nodes.
			continue
		}
		member := isNPMWorkspaceMemberPath(packagePath)
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			name = npmNameFromPackagePath(packagePath)
		}
		if name == "" && member {
			name = filepath.Base(strings.TrimSuffix(filepath.ToSlash(packagePath), "/"))
		}
		if name == "" {
			continue
		}
		pkg := sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM,
			Name:    name,
			Version: entry.Version}, Scopes: sdk.ScopesOf(scopeFromNPMLockPackage(entry)),
			ResolvedURL: entry.Resolved,
			Digests:     node.ParseIntegrityDigests(entry.Integrity),
		}
		if member {
			// Workspace members are local applications, not fetched packages.
			pkg.Type = sdk.PackageTypeApplication
			pkg.ResolvedURL = ""
		}
		if meta := npmLockPackageMetadata(entry); meta != nil {
			pkg.Metadata = map[string]any{sdk.MetadataKeyNPM: meta}
		}
		pkgNode := sdk.NewDependency(pkg)
		if entry.License != "" {
			sdk.SetDetectionLicenses(pkgNode, []sdk.PackageLicense{{Value: entry.License, Type: "declared"}})
		}
		if err := node.AddNodeIfMissing(depsGraph, pkgNode); err != nil {
			return npmLockfileGraphs{}, err
		}
		pathToID[packagePath] = pkgNode.ID
		if member {
			modules = append(modules, npmModuleGraph{dir: strings.TrimPrefix(filepath.ToSlash(packagePath), "./"), rootID: pkgNode.ID})
		}
	}

	// Alias link entries onto the local directories they point at so
	// dependencies on "node_modules/<member>" resolve to the member's node
	// instead of synthesizing a duplicate, versionless package.
	for _, packagePath := range paths {
		entry := lockfile.Packages[packagePath]
		if !entry.Link {
			continue
		}
		target := strings.TrimPrefix(strings.TrimSpace(strings.ReplaceAll(entry.Resolved, "\\", "/")), "./")
		if id, ok := pathToID[target]; ok {
			pathToID[packagePath] = id
		}
	}

	for _, packagePath := range paths {
		entry := lockfile.Packages[packagePath]
		if entry.Link {
			continue
		}
		parentID := rootNode.ID
		if packagePath != "" {
			id, ok := pathToID[packagePath]
			if !ok {
				continue
			}
			parentID = id
		}
		for dependencyName, dependencyVersion := range packageDependencyVersions(packagePath, entry) {
			targetID, ok := resolveNPMLockDependencyID(packagePath, dependencyName, dependencyVersion, lockfile, pathToID)
			if !ok {
				synthetic := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: dependencyName, Version: node.NormalizeVersionToken(dependencyVersion)}})
				if err := node.AddNodeIfMissing(depsGraph, synthetic); err != nil {
					return npmLockfileGraphs{}, err
				}
				targetID = synthetic.ID
			}
			if err := depsGraph.AddEdge(parentID, targetID); err != nil {
				return npmLockfileGraphs{}, fmt.Errorf("add npm dependency %q -> %q: %w", parentID, targetID, err)
			}
		}
	}

	if rootEntry, ok := lockfile.Packages[""]; ok {
		node.ApplyDirectDependencyScopes(depsGraph, rootNode.ID, npmRootDirectScopes(rootEntry))
	}
	for _, module := range modules {
		if entry, ok := lockfile.Packages[module.dir]; ok {
			node.ApplyDirectDependencyScopes(depsGraph, module.rootID, npmRootDirectScopes(entry))
		}
	}
	return npmLockfileGraphs{graph: depsGraph, rootID: rootNode.ID, modules: modules}, nil
}

// isNPMWorkspaceMemberPath reports whether a packages-map key addresses a
// local source directory (npm writes workspace members and file: dependencies
// by their directory) rather than an installed node_modules entry or the root.
func isNPMWorkspaceMemberPath(packagePath string) bool {
	normalized := strings.TrimPrefix(strings.ReplaceAll(packagePath, "\\", "/"), "./")
	if normalized == "" || normalized == "." {
		return false
	}
	return normalized != "node_modules" &&
		!strings.HasPrefix(normalized, "node_modules/") &&
		!strings.Contains(normalized, "/node_modules/")
}

func packageDependencyVersions(packagePath string, entry npmLockPackage) map[string]string {
	deps := node.MergeStringMaps(entry.Dependencies, entry.OptionalDependencies)
	// Dev dependencies are edges only for local application roots — the
	// lockfile root and workspace members — never for installed packages.
	if packagePath == "" || isNPMWorkspaceMemberPath(packagePath) {
		deps = node.MergeStringMaps(deps, entry.DevDependencies)
	}
	return deps
}

func npmRootDirectScopes(root npmLockPackage) map[string]sdk.Scope {
	directScopes := make(map[string]sdk.Scope, len(root.Dependencies)+len(root.OptionalDependencies)+len(root.PeerDependencies)+len(root.DevDependencies))
	recordDependencyScopes(directScopes, root.Dependencies, sdk.ScopeRuntime)
	recordDependencyScopes(directScopes, root.OptionalDependencies, sdk.ScopeRuntime)
	recordDependencyScopes(directScopes, root.PeerDependencies, sdk.ScopeRuntime)
	recordDependencyScopes(directScopes, root.DevDependencies, sdk.ScopeDevelopment)
	return directScopes
}

func recordDependencyScopes(target map[string]sdk.Scope, dependencies map[string]string, scope sdk.Scope) {
	for name := range dependencies {
		target[name] = sdk.MergeScope(target[name], scope)
	}
}

func resolveNPMLockDependencyID(parentPath string, dependencyName string, dependencyVersion string, lockfile npmPackageLock, pathToID map[string]string) (string, bool) {
	searchBase := strings.TrimPrefix(strings.TrimSpace(strings.ReplaceAll(parentPath, "\\", "/")), "./")
	for {
		candidate := "node_modules/" + dependencyName
		if searchBase != "" {
			candidate = searchBase + "/node_modules/" + dependencyName
		}
		if id, ok := pathToID[candidate]; ok {
			return id, true
		}
		if searchBase == "" {
			break
		}
		if idx := strings.LastIndex(searchBase, "/node_modules/"); idx >= 0 {
			searchBase = searchBase[:idx]
			continue
		}
		if strings.HasPrefix(searchBase, "node_modules/") {
			searchBase = ""
			continue
		}
		break
	}

	normalizedDepVersion := node.NormalizeVersionToken(dependencyVersion)
	paths := make([]string, 0, len(lockfile.Packages))
	for packagePath := range lockfile.Packages {
		if packagePath == "" {
			continue
		}
		paths = append(paths, packagePath)
	}
	sort.Strings(paths)
	for _, packagePath := range paths {
		entry := lockfile.Packages[packagePath]
		if packagePath == "" {
			continue
		}
		name := entry.Name
		if name == "" {
			name = npmNameFromPackagePath(packagePath)
		}
		if name != dependencyName {
			continue
		}
		if normalizedDepVersion == "" || node.NormalizeVersionToken(entry.Version) == normalizedDepVersion {
			if id, ok := pathToID[packagePath]; ok {
				return id, true
			}
		}
	}
	for _, packagePath := range paths {
		entry := lockfile.Packages[packagePath]
		if packagePath == "" {
			continue
		}
		name := entry.Name
		if name == "" {
			name = npmNameFromPackagePath(packagePath)
		}
		if name != dependencyName {
			continue
		}
		if id, ok := pathToID[packagePath]; ok {
			return id, true
		}
	}
	return "", false
}

func npmNameFromPackagePath(packagePath string) string {
	trimmed := strings.TrimSpace(strings.TrimPrefix(packagePath, "./"))
	if trimmed == "" {
		return ""
	}
	idx := strings.LastIndex(trimmed, "node_modules/")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(trimmed[idx+len("node_modules/"):])
}

func scopeFromNPMLockPackage(entry npmLockPackage) sdk.Scope {
	if entry.Dev {
		if entry.Optional {
			return sdk.ScopeDevelopment
		}
		return sdk.ScopeDevelopment
	}
	if entry.Optional {
		return sdk.ScopeRuntime
	}
	return sdk.ScopeUnknown
}
