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
	Name                     string            `json:"name"`
	Version                  string            `json:"version"`
	Resolved                 string            `json:"resolved"`
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
		meta.Engines = map[string]string(entry.Engines)
	}
	return meta
}

func depGraphFromNPMLockfile(projectPath string) (*sdk.Graph, error) {
	raw, err := os.ReadFile(filepath.Join(projectPath, "package-lock.json"))
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}

	var lockfile npmPackageLock
	if err := json.Unmarshal(raw, &lockfile); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	// Prefer the packages-map path (v2/v3) when available: it carries richer metadata
	// (resolved URL, integrity, license, engines). Fall back to the flat dependencies path
	// only for v1 lockfiles that have no packages map.
	if len(lockfile.Packages) == 0 {
		if len(lockfile.Dependencies) == 0 {
			return nil, errors.New("package-lock.json has no dependencies")
		}
		root := &node.NPMListNode{Name: lockfile.Name, Version: lockfile.Version, Dependencies: lockfile.Dependencies}
		if root.Name == "" {
			root.Name = "root"
		}
		return node.DepGraphFromNPMNode(root)
	}

	depsGraph := sdk.New()
	rootName := lockfile.Name
	if rootName == "" {
		rootName = "root"
	}
	rootNode := sdk.NewPackage(sdk.Package{Ecosystem: string(sdk.EcosystemNPM), Name: rootName, Version: lockfile.Version, Type: "application"})
	if err := depsGraph.AddPackage(rootNode); err != nil {
		return nil, fmt.Errorf("add npm root node: %w", err)
	}

	paths := make([]string, 0, len(lockfile.Packages))
	for packagePath := range lockfile.Packages {
		paths = append(paths, packagePath)
	}
	sort.Strings(paths)

	pathToID := map[string]string{"": rootNode.ID}
	for _, packagePath := range paths {
		if packagePath == "" {
			continue
		}
		entry := lockfile.Packages[packagePath]
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			name = npmNameFromPackagePath(packagePath)
		}
		if name == "" {
			continue
		}
		pkg := sdk.Package{
			Ecosystem:   string(sdk.EcosystemNPM),
			Name:        name,
			Version:     entry.Version,
			Scope:       string(scopeFromNPMLockPackage(entry)),
			ResolvedURL: entry.Resolved,
			Digests:     node.ParseIntegrityDigests(entry.Integrity),
		}
		if entry.License != "" {
			pkg.Licenses = []sdk.PackageLicense{{Value: entry.License, Type: "declared"}}
		}
		if meta := npmLockPackageMetadata(entry); meta != nil {
			pkg.Metadata = map[string]any{sdk.MetadataKeyNPM: meta}
		}
		pkgNode := sdk.NewPackage(pkg)
		if err := node.AddNodeIfMissing(depsGraph, pkgNode); err != nil {
			return nil, err
		}
		pathToID[packagePath] = pkgNode.ID
	}

	for _, packagePath := range paths {
		entry := lockfile.Packages[packagePath]
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
				synthetic := sdk.NewPackage(sdk.Package{Ecosystem: string(sdk.EcosystemNPM), Name: dependencyName, Version: node.NormalizeVersionToken(dependencyVersion)})
				if err := node.AddNodeIfMissing(depsGraph, synthetic); err != nil {
					return nil, err
				}
				targetID = synthetic.ID
			}
			if err := depsGraph.AddDependency(parentID, targetID); err != nil {
				return nil, fmt.Errorf("add npm dependency %q -> %q: %w", parentID, targetID, err)
			}
		}
	}

	if rootEntry, ok := lockfile.Packages[""]; ok {
		node.ApplyDirectDependencyScopes(depsGraph, rootNode.ID, npmRootDirectScopes(rootEntry))
	}
	return depsGraph, nil
}

func packageDependencyVersions(packagePath string, entry npmLockPackage) map[string]string {
	deps := node.MergeStringMaps(entry.Dependencies, entry.OptionalDependencies)
	if packagePath == "" {
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
