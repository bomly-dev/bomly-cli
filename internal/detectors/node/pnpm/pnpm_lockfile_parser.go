package pnpm

import (
	"errors"
	"fmt"
	"io"
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
	Dependencies         map[string]any    `yaml:"dependencies"`
	OptionalDependencies map[string]any    `yaml:"optionalDependencies"`
	License              string            `yaml:"license"`
	Engines              map[string]string `yaml:"engines"`
}

type resolvedPackage struct {
	id      string
	name    string
	version string
}

// pnpmModuleGraph identifies one workspace importer inside the parsed
// lockfile graph: the importer's directory (relative to the project root,
// slash form) and its application root node in the merged graph.
type pnpmModuleGraph struct {
	dir    string
	rootID string
}

// pnpmLockfileGraphs carries the merged lockfile graph plus the workspace
// importer roots the detector partitions into per-module manifest entries.
type pnpmLockfileGraphs struct {
	graph   *sdk.Graph
	rootID  string
	modules []pnpmModuleGraph
}

func depGraphFromPNPMLockfile(projectPath string) (pnpmLockfileGraphs, error) {
	raw, err := os.ReadFile(filepath.Join(projectPath, "pnpm-lock.yaml"))
	if err != nil {
		return pnpmLockfileGraphs{}, fmt.Errorf("read pnpm-lock.yaml: %w", err)
	}

	lockfile, err := parsePNPMLockfile(raw)
	if err != nil {
		return pnpmLockfileGraphs{}, fmt.Errorf("parse pnpm-lock.yaml: %w", err)
	}
	major, err := pnpmLockfileMajor(lockfile.LockfileVersion)
	if err != nil || (major != 5 && major != 6 && major < 9) {
		return pnpmLockfileGraphs{}, fmt.Errorf("unsupported pnpm lockfileVersion %v (supported: 5.x, 6.x, 9+)", lockfile.LockfileVersion)
	}
	if len(lockfile.Packages) == 0 {
		return pnpmLockfileGraphs{}, errors.New("pnpm-lock.yaml has no packages")
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
	rootNode := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: rootName, Version: manifest.Version, Type: sdk.PackageTypeApplication}, Source: sdk.DependencySourceProject})
	depsGraph := sdk.New()
	if err := depsGraph.AddNode(rootNode); err != nil {
		return pnpmLockfileGraphs{}, fmt.Errorf("add pnpm root node: %w", err)
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
		pkg := sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM,
			Name:    name,
			Version: version}, Source: pnpmPackageSource(key, entry), ResolvedURL: entry.Resolution.Tarball,
			Digests: node.ParseIntegrityDigests(entry.Resolution.Integrity),
		}
		if entry.Resolution.Integrity == "" && entry.Resolution.Hash != "" {
			pkg.Digests = []sdk.Digest{{Algorithm: sdk.DigestAlgorithmSHA1, Value: entry.Resolution.Hash}}
		}
		if len(entry.Engines) > 0 {
			pkg.Metadata = map[string]any{sdk.MetadataKeyNPM: &sdk.NPMPackageMetadata{Engines: entry.Engines}}
		}
		pkgNode := sdk.NewDependency(pkg)
		if existing, ok := depsGraph.Node(pkgNode.ID); ok && existing.Type == sdk.PackageTypeApplication {
			pkgNode = sdk.NewDependencyWithID("pnpm-package:"+key, pkg)
		}
		if entry.License != "" {
			sdk.SetDetectionLicenses(pkgNode, []sdk.PackageLicense{{Value: entry.License, Type: "declared"}})
		}
		if err := node.AddNodeIfMissing(depsGraph, pkgNode); err != nil {
			return pnpmLockfileGraphs{}, err
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
		for dependencyName, dependencyVersion := range mergeAnyMaps(entry.Dependencies, entry.OptionalDependencies) {
			resolvedName, resolvedVersion := pnpmAliasTarget(dependencyName, dependencyVersion)
			resolved, ok := resolvePNPMDependency(byName, resolvedName, resolvedVersion)
			if !ok {
				synthetic := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: resolvedName, Version: node.NormalizeVersionToken(resolvedVersion)}, Source: node.DependencySourceFromSpecifier(resolvedVersion)})
				if err := node.AddNodeIfMissing(depsGraph, synthetic); err != nil {
					return pnpmLockfileGraphs{}, err
				}
				resolved = resolvedPackage{id: synthetic.ID, name: dependencyName, version: node.NormalizeVersionToken(dependencyVersion)}
			}
			if parent.id == resolved.id {
				continue
			}
			if err := depsGraph.AddEdge(parent.id, resolved.id); err != nil {
				return pnpmLockfileGraphs{}, fmt.Errorf("add pnpm dependency %q -> %q: %w", parent.id, resolved.id, err)
			}
		}
	}

	// Workspace importers: "." is the root; every other importer is a member
	// with its own application root node and manifest entry. Importers were
	// previously only wired for "." — member direct-dependency edges (and
	// workspace link: dependencies between members) were silently dropped.
	memberByDir := map[string]string{".": rootNode.ID}
	memberByName := map[string]string{rootName: rootNode.ID}
	modules := make([]pnpmModuleGraph, 0)
	importerDirs := make([]string, 0, len(lockfile.Importers))
	for dir := range lockfile.Importers {
		importerDirs = append(importerDirs, dir)
	}
	sort.Strings(importerDirs)
	for _, dir := range importerDirs {
		if dir == "." {
			continue
		}
		cleanDir := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(dir)), "./")
		memberManifest, _ := node.ReadPackageJSONManifest(filepath.Join(projectPath, filepath.FromSlash(cleanDir)))
		memberName := memberManifest.Name
		if memberName == "" {
			memberName = filepath.Base(cleanDir)
		}
		memberDep := sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: memberName, Version: memberManifest.Version, Type: sdk.PackageTypeApplication}, Source: sdk.DependencySourceWorkspace}
		memberNode := sdk.NewDependency(memberDep)
		if _, exists := depsGraph.Node(memberNode.ID); exists {
			memberNode = sdk.NewDependencyWithID("workspace:"+cleanDir, memberDep)
		}
		if err := node.AddNodeIfMissing(depsGraph, memberNode); err != nil {
			return pnpmLockfileGraphs{}, err
		}
		memberByDir[cleanDir] = memberNode.ID
		memberByName[memberName] = memberNode.ID
		modules = append(modules, pnpmModuleGraph{dir: cleanDir, rootID: memberNode.ID})
	}

	if len(lockfile.Importers) > 0 {
		for _, dir := range importerDirs {
			importer := lockfile.Importers[dir]
			cleanDir := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(dir)), "./")
			parentID, ok := memberByDir[cleanDir]
			if !ok {
				continue
			}
			deps := mergeAnyMaps(importer.Dependencies, importer.OptionalDependencies)
			for dependencyName, dependencyVersion := range importer.DevDependencies {
				deps[dependencyName] = versionFromPNPMAny(dependencyVersion)
			}
			for dependencyName, dependencyVersion := range deps {
				targetID, ok := resolvePNPMImporterDependency(byName, memberByDir, memberByName, cleanDir, dependencyName, dependencyVersion)
				if !ok {
					resolvedName, resolvedVersion := pnpmAliasTarget(dependencyName, dependencyVersion)
					synthetic := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: resolvedName, Version: node.NormalizeVersionToken(resolvedVersion)}, Source: node.DependencySourceFromSpecifier(dependencyVersion)})
					if err := node.AddNodeIfMissing(depsGraph, synthetic); err != nil {
						return pnpmLockfileGraphs{}, err
					}
					targetID = synthetic.ID
				}
				if parentID == targetID {
					continue
				}
				if err := depsGraph.AddEdge(parentID, targetID); err != nil {
					return pnpmLockfileGraphs{}, fmt.Errorf("add pnpm importer dependency %q -> %q: %w", parentID, targetID, err)
				}
			}
			node.ApplyDirectDependencyScopes(depsGraph, parentID, pnpmImporterDirectScopes(importer))
		}
	} else {
		// Old pnpm lockfile format (pre-importers): root-level dependency tables.
		runtimeDeps := mergeAnyMaps(lockfile.Dependencies, lockfile.OptionalDependencies)
		for dependencyName, dependencyVersion := range runtimeDeps {
			resolved, ok := resolvePNPMDependency(byName, dependencyName, dependencyVersion)
			if !ok {
				continue
			}
			if err := depsGraph.AddEdge(rootNode.ID, resolved.id); err != nil {
				return pnpmLockfileGraphs{}, fmt.Errorf("add pnpm root dependency %q -> %q: %w", rootNode.ID, resolved.id, err)
			}
		}
		for dependencyName, dependencyVersion := range lockfile.DevDependencies {
			resolved, ok := resolvePNPMDependency(byName, dependencyName, versionFromPNPMAny(dependencyVersion))
			if !ok {
				continue
			}
			if err := depsGraph.AddEdge(rootNode.ID, resolved.id); err != nil {
				return pnpmLockfileGraphs{}, fmt.Errorf("add pnpm root dev dependency %q -> %q: %w", rootNode.ID, resolved.id, err)
			}
		}
		node.ApplyDirectDependencyScopes(depsGraph, rootNode.ID, pnpmRootDirectScopes(lockfile))
	}

	return pnpmLockfileGraphs{graph: depsGraph, rootID: rootNode.ID, modules: modules}, nil
}

// resolvePNPMImporterDependency resolves one importer dependency edge target:
// "link:" version specs point at another workspace importer directory
// (relative to the importer), everything else resolves through the package
// tables.
func resolvePNPMImporterDependency(byName map[string][]resolvedPackage, memberByDir, memberByName map[string]string, importerDir, dependencyName, dependencyVersion string) (string, bool) {
	version := strings.TrimSpace(dependencyVersion)
	if strings.HasPrefix(version, "workspace:") {
		id, ok := memberByName[dependencyName]
		return id, ok
	}
	if strings.HasPrefix(version, "link:") || strings.HasPrefix(version, "file:") {
		target := strings.TrimPrefix(strings.TrimPrefix(version, "link:"), "file:")
		base := importerDir
		if base == "." {
			base = ""
		}
		resolvedDir := filepath.ToSlash(filepath.Clean(filepath.Join(base, filepath.FromSlash(target))))
		resolvedDir = strings.TrimPrefix(resolvedDir, "./")
		if resolvedDir == "" {
			resolvedDir = "."
		}
		id, ok := memberByDir[resolvedDir]
		if ok {
			return id, true
		}
	}
	resolvedName, resolvedVersion := pnpmAliasTarget(dependencyName, version)
	resolved, ok := resolvePNPMDependency(byName, resolvedName, resolvedVersion)
	if !ok {
		return "", false
	}
	return resolved.id, true
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
	// Legacy keys use /name/version and /@scope/name/version.
	if strings.HasPrefix(strings.TrimSpace(key), "/") {
		parts := strings.Split(value, "/")
		if len(parts) >= 3 && strings.HasPrefix(parts[0], "@") {
			return parts[0] + "/" + parts[1], normalizePNPMLegacyVersion(parts[2])
		}
		if len(parts) >= 2 {
			return parts[0], normalizePNPMLegacyVersion(parts[1])
		}
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

func normalizePNPMLegacyVersion(value string) string {
	if idx := strings.Index(value, "_"); idx > 0 {
		value = value[:idx]
	}
	return node.NormalizeVersionToken(value)
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
			return fmt.Sprint(raw)
		}
	case map[any]any:
		if raw, ok := typed["version"]; ok {
			return fmt.Sprint(raw)
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

func parsePNPMLockfile(raw []byte) (pnpmLockfile, error) {
	decoder := yaml.NewDecoder(strings.NewReader(string(node.StripUTF8BOM(raw))))
	var documents []pnpmLockfile
	for {
		var document pnpmLockfile
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return pnpmLockfile{}, err
		}
		if document.LockfileVersion != nil || len(document.Packages) > 0 || len(document.Snapshots) > 0 || len(document.Importers) > 0 {
			documents = append(documents, document)
		}
	}
	if len(documents) == 0 {
		return pnpmLockfile{}, errors.New("pnpm-lock.yaml is empty")
	}
	for _, document := range documents {
		for _, importer := range document.Importers {
			if len(importer.Dependencies)+len(importer.OptionalDependencies)+len(importer.DevDependencies) > 0 {
				return document, nil
			}
		}
	}
	for _, document := range documents {
		if len(document.Packages) > 0 || len(document.Snapshots) > 0 {
			return document, nil
		}
	}
	return pnpmLockfile{}, errors.New("no project lockfile document found")
}

func pnpmLockfileMajor(value any) (int, error) {
	text := strings.TrimSpace(fmt.Sprint(value))
	if idx := strings.Index(text, "."); idx >= 0 {
		text = text[:idx]
	}
	var major int
	if _, err := fmt.Sscanf(text, "%d", &major); err != nil || major <= 0 {
		return 0, fmt.Errorf("invalid lockfile version %q", text)
	}
	return major, nil
}

func pnpmAliasTarget(name, version string) (string, string) {
	value := strings.TrimSpace(version)
	if !strings.HasPrefix(value, "npm:") {
		return name, value
	}
	value = strings.TrimPrefix(value, "npm:")
	idx := strings.LastIndex(value, "@")
	if idx <= 0 {
		return name, value
	}
	return value[:idx], value[idx+1:]
}

func pnpmPackageSource(key string, entry pnpmLockPackage) sdk.DependencySource {
	value := strings.TrimSpace(key)
	if entry.Version != "" {
		value = entry.Version
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"workspace:", "link:", "file:", "git:", "git+", "github:", "http:", "https:"} {
		if idx := strings.Index(lower, marker); idx >= 0 {
			value = value[idx:]
			break
		}
	}
	return node.DependencySourceFromSpecifier(value)
}
