package pnpm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/sdk"
	"gopkg.in/yaml.v3"
)

type pnpmResolution struct {
	Integrity string `yaml:"integrity"`
	Tarball   string `yaml:"tarball"`
	Hash      string `yaml:"hash"`
}

type pnpmLockfile struct {
	LockfileVersion any                     `yaml:"lockfileVersion"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
	// Old pnpm format (pre-importers): root-level dependency tables.
	Dependencies         map[string]any             `yaml:"dependencies"`
	DevDependencies      map[string]any             `yaml:"devDependencies"`
	OptionalDependencies map[string]any             `yaml:"optionalDependencies"`
	Packages             map[string]pnpmLockPackage `yaml:"packages"`
	// pnpm v9+: package metadata and dependency edges are split across packages and snapshots.
	Snapshots map[string]pnpmLockPackage `yaml:"snapshots"`
}

type pnpmImporter struct {
	Dependencies         map[string]any `yaml:"dependencies"`
	DevDependencies      map[string]any `yaml:"devDependencies"`
	OptionalDependencies map[string]any `yaml:"optionalDependencies"`
}

type pnpmLockPackage struct {
	Version              string            `yaml:"version"`
	Resolution           pnpmResolution    `yaml:"resolution"`
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
	License              string            `yaml:"license"`
	Engines              map[string]string `yaml:"engines"`
}

type resolvedPackage struct {
	id      string
	name    string
	version string
}

func depGraphFromPNPMLockfile(projectPath string) (*sdk.Graph, error) {
	raw, err := os.ReadFile(filepath.Join(projectPath, "pnpm-lock.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read pnpm-lock.yaml: %w", err)
	}

	var lockfile pnpmLockfile
	if err := yaml.Unmarshal(raw, &lockfile); err != nil {
		return nil, fmt.Errorf("parse pnpm-lock.yaml: %w", err)
	}
	if len(lockfile.Packages) == 0 {
		return nil, errors.New("pnpm-lock.yaml has no packages")
	}

	// In pnpm v9+, packages section has metadata (resolution, license) and snapshots
	// section has dependency edges. Use snapshots for dependency edges when available.
	edgeSource := lockfile.Packages
	if len(lockfile.Snapshots) > 0 {
		edgeSource = lockfile.Snapshots
	}

	manifest, _ := node.ReadPackageJSONManifest(projectPath)
	rootName := manifest.Name
	if rootName == "" {
		rootName = "root"
	}
	rootNode := sdk.NewPackage(sdk.Package{Ecosystem: string(sdk.EcosystemNPM), Name: rootName, Version: manifest.Version, Type: "application"})
	depsGraph := sdk.New()
	if err := depsGraph.AddPackage(rootNode); err != nil {
		return nil, fmt.Errorf("add pnpm root node: %w", err)
	}

	byKey := make(map[string]resolvedPackage, len(lockfile.Packages))
	byName := make(map[string][]resolvedPackage)

	keys := make([]string, 0, len(lockfile.Packages))
	for key := range lockfile.Packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := lockfile.Packages[key]
		name, version := parsePNPMPackageKey(key, entry.Version)
		if name == "" {
			continue
		}
		pkg := sdk.Package{
			Ecosystem:   string(sdk.EcosystemNPM),
			Name:        name,
			Version:     version,
			ResolvedURL: entry.Resolution.Tarball,
			Digests:     node.ParseIntegrityDigests(entry.Resolution.Integrity),
		}
		if entry.Resolution.Integrity == "" && entry.Resolution.Hash != "" {
			pkg.Digests = []sdk.Digest{{Algorithm: "sha1", Value: entry.Resolution.Hash}}
		}
		if entry.License != "" {
			pkg.Licenses = []sdk.PackageLicense{{Value: entry.License, Type: "declared"}}
		}
		if len(entry.Engines) > 0 {
			pkg.Metadata = map[string]any{sdk.MetadataKeyNPM: &sdk.NPMPackageMetadata{Engines: entry.Engines}}
		}
		pkgNode := sdk.NewPackage(pkg)
		if err := node.AddNodeIfMissing(depsGraph, pkgNode); err != nil {
			return nil, err
		}
		resolved := resolvedPackage{id: pkgNode.ID, name: name, version: node.NormalizeVersionToken(version)}
		byKey[key] = resolved
		byName[name] = append(byName[name], resolved)
	}

	// Build the set of all edge-source keys (snapshots in v9, packages in older versions).
	// When using snapshots, we may have keys that differ from packages keys (e.g. with peer suffix).
	// Iterate over edgeSource keys for dependency resolution.
	edgeKeys := keys
	if len(lockfile.Snapshots) > 0 {
		edgeKeys = make([]string, 0, len(lockfile.Snapshots))
		for key := range lockfile.Snapshots {
			edgeKeys = append(edgeKeys, key)
		}
		sort.Strings(edgeKeys)
	}

	for _, key := range edgeKeys {
		entry := edgeSource[key]
		// Map snapshot keys back to packages keys for parent lookup.
		// Snapshot keys may have a peer-suffix like "foo@1.0.0(bar@2.0.0)"; strip it.
		packageKey := pnpmStripPeerSuffix(key)
		parent, ok := byKey[packageKey]
		if !ok {
			parent, ok = byKey[key]
		}
		if !ok {
			continue
		}
		for dependencyName, dependencyVersion := range node.MergeStringMaps(entry.Dependencies, entry.OptionalDependencies) {
			resolved, ok := resolvePNPMDependency(byName, dependencyName, dependencyVersion)
			if !ok {
				synthetic := sdk.NewPackage(sdk.Package{Ecosystem: string(sdk.EcosystemNPM), Name: dependencyName, Version: node.NormalizeVersionToken(dependencyVersion)})
				if err := node.AddNodeIfMissing(depsGraph, synthetic); err != nil {
					return nil, err
				}
				resolved = resolvedPackage{id: synthetic.ID, name: dependencyName, version: node.NormalizeVersionToken(dependencyVersion)}
			}
			if err := depsGraph.AddDependency(parent.id, resolved.id); err != nil {
				return nil, fmt.Errorf("add pnpm dependency %q -> %q: %w", parent.id, resolved.id, err)
			}
		}
	}

	if importer, ok := lockfile.Importers["."]; ok {
		runtimeDeps := mergeAnyMaps(importer.Dependencies, importer.OptionalDependencies)
		for dependencyName, dependencyVersion := range runtimeDeps {
			resolved, ok := resolvePNPMDependency(byName, dependencyName, dependencyVersion)
			if !ok {
				continue
			}
			if err := depsGraph.AddDependency(rootNode.ID, resolved.id); err != nil {
				return nil, fmt.Errorf("add pnpm root dependency %q -> %q: %w", rootNode.ID, resolved.id, err)
			}
		}
		for dependencyName, dependencyVersion := range importer.DevDependencies {
			resolved, ok := resolvePNPMDependency(byName, dependencyName, versionFromPNPMAny(dependencyVersion))
			if !ok {
				continue
			}
			if err := depsGraph.AddDependency(rootNode.ID, resolved.id); err != nil {
				return nil, fmt.Errorf("add pnpm root dev dependency %q -> %q: %w", rootNode.ID, resolved.id, err)
			}
		}
		node.ApplyDirectDependencyScopes(depsGraph, rootNode.ID, pnpmImporterDirectScopes(importer))
	} else {
		// Old pnpm lockfile format (pre-importers): root-level dependency tables.
		runtimeDeps := mergeAnyMaps(lockfile.Dependencies, lockfile.OptionalDependencies)
		for dependencyName, dependencyVersion := range runtimeDeps {
			resolved, ok := resolvePNPMDependency(byName, dependencyName, dependencyVersion)
			if !ok {
				continue
			}
			if err := depsGraph.AddDependency(rootNode.ID, resolved.id); err != nil {
				return nil, fmt.Errorf("add pnpm root dependency %q -> %q: %w", rootNode.ID, resolved.id, err)
			}
		}
		for dependencyName, dependencyVersion := range lockfile.DevDependencies {
			resolved, ok := resolvePNPMDependency(byName, dependencyName, versionFromPNPMAny(dependencyVersion))
			if !ok {
				continue
			}
			if err := depsGraph.AddDependency(rootNode.ID, resolved.id); err != nil {
				return nil, fmt.Errorf("add pnpm root dev dependency %q -> %q: %w", rootNode.ID, resolved.id, err)
			}
		}
		node.ApplyDirectDependencyScopes(depsGraph, rootNode.ID, pnpmRootDirectScopes(lockfile))
	}

	return depsGraph, nil
}

func pnpmImporterDirectScopes(importer pnpmImporter) map[string]sdk.Scope {
	directScopes := make(map[string]sdk.Scope, len(importer.Dependencies)+len(importer.OptionalDependencies)+len(importer.DevDependencies))
	recordPNPMDependencyScopes(directScopes, importer.Dependencies, sdk.ScopeRuntime)
	recordPNPMDependencyScopes(directScopes, importer.OptionalDependencies, sdk.ScopeRuntime)
	recordPNPMDependencyScopes(directScopes, importer.DevDependencies, sdk.ScopeDevelopment)
	return directScopes
}

func pnpmRootDirectScopes(lockfile pnpmLockfile) map[string]sdk.Scope {
	directScopes := make(map[string]sdk.Scope, len(lockfile.Dependencies)+len(lockfile.OptionalDependencies)+len(lockfile.DevDependencies))
	recordPNPMDependencyScopes(directScopes, lockfile.Dependencies, sdk.ScopeRuntime)
	recordPNPMDependencyScopes(directScopes, lockfile.OptionalDependencies, sdk.ScopeRuntime)
	recordPNPMDependencyScopes(directScopes, lockfile.DevDependencies, sdk.ScopeDevelopment)
	return directScopes
}

func recordPNPMDependencyScopes(target map[string]sdk.Scope, dependencies map[string]any, scope sdk.Scope) {
	for name := range dependencies {
		target[name] = sdk.MergeScope(target[name], scope)
	}
}

func parsePNPMPackageKey(key string, fallbackVersion string) (string, string) {
	value := strings.TrimPrefix(strings.TrimSpace(key), "/")
	if value == "" {
		return "", node.NormalizeVersionToken(fallbackVersion)
	}
	idx := strings.LastIndex(value, "@")
	if idx <= 0 {
		return value, node.NormalizeVersionToken(fallbackVersion)
	}
	name := value[:idx]
	version := value[idx+1:]
	if slash := strings.LastIndex(name, "/"); slash >= 0 && strings.HasPrefix(name, "node_modules/") {
		name = name[slash+1:]
	}
	return name, node.NormalizeVersionToken(version)
}

func resolvePNPMDependency(byName map[string][]resolvedPackage, dependencyName string, rawVersion string) (resolvedPackage, bool) {
	candidates := byName[dependencyName]
	if len(candidates) == 0 {
		return resolvedPackage{}, false
	}
	version := node.NormalizeVersionToken(rawVersion)
	for _, candidate := range candidates {
		if version == "" || candidate.version == version {
			return candidate, true
		}
	}
	return candidates[0], true
}

func versionFromPNPMAny(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case map[string]any:
		if raw, ok := typed["version"]; ok {
			if version, ok := raw.(string); ok {
				return version
			}
		}
	}
	return ""
}

func mergeAnyMaps(left map[string]any, right map[string]any) map[string]string {
	out := make(map[string]string, len(left)+len(right))
	for key, value := range left {
		out[key] = versionFromPNPMAny(value)
	}
	for key, value := range right {
		out[key] = versionFromPNPMAny(value)
	}
	return out
}

// pnpmStripPeerSuffix strips the peer dependency suffix from a pnpm v9 snapshot key.
// For example: "express@4.18.2(peer-dep@1.0.0)" -> "express@4.18.2".
func pnpmStripPeerSuffix(key string) string {
	idx := strings.Index(key, "(")
	if idx < 0 {
		return key
	}
	return key[:idx]
}
