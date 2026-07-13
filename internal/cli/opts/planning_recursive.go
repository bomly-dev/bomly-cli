package opts

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// defaultDiscoverySkipDirs are directory names the recursive walk never
// descends into, in addition to any name starting with a dot. They hold
// third-party installs, vendored dependencies, or build outputs that commonly
// contain copied manifests (Maven copies pom.xml into target/, bundlers copy
// package.json into dist/), so walking them produces duplicate or misleading
// subprojects. Directories containing a pyvenv.cfg file (non-hidden Python
// virtualenvs) are skipped via shouldSkipDiscoveryDir's probe.
var defaultDiscoverySkipDirs = map[string]struct{}{
	"node_modules": {},
	"vendor":       {},
	"target":       {},
	"build":        {},
	"dist":         {},
	"__pycache__":  {},
}

// nativeMultiModulePackageManagers lists package managers whose primary
// detectors expand nested workspace/reactor modules from the root manifest
// (Maven reactor TGF blocks, Gradle settings subprojects, npm/pnpm/yarn
// workspaces, cargo metadata workspace_members, sbt aggregated builds, mix
// umbrella apps). When one of these is detected at an ancestor directory,
// nested manifests for the same manager resolve through the ancestor and must
// not become their own subprojects, or the same modules would be scanned
// twice. Managers absent from this set (gomod, pip/poetry/uv, bundler,
// composer, ...) treat every nested manifest as an independent project:
// notably a nested go.mod is excluded from the parent Go module by language
// semantics, so it must be scanned on its own.
var nativeMultiModulePackageManagers = map[sdk.PackageManager]struct{}{
	sdk.PackageManagerMaven:  {},
	sdk.PackageManagerGradle: {},
	sdk.PackageManagerNPM:    {},
	sdk.PackageManagerPNPM:   {},
	sdk.PackageManagerYarn:   {},
	sdk.PackageManagerCargo:  {},
	sdk.PackageManagerSBT:    {},
	sdk.PackageManagerMix:    {},
}

// planRecursiveFilesystemSubprojects walks the execution-target directory tree
// and plans subprojects for every directory with recognized manifest evidence,
// honoring the request's depth cap, exclude globs, the built-in skip rules,
// and per-package-manager ancestor pruning.
func planRecursiveFilesystemSubprojects(registryValue *engine.Registry, req Request) ([]sdk.Subproject, error) {
	logger := req.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	absRoot, err := filepath.Abs(req.ExecutionTarget.Location)
	if err != nil {
		return nil, fmt.Errorf("resolve recursive discovery root: %w", err)
	}
	// filepath.WalkDir lstats the root and does not descend when the root
	// itself is a symlink, so resolve it up front. Directory symlinks below
	// the root are intentionally not followed.
	if resolved, symlinkErr := filepath.EvalSymlinks(absRoot); symlinkErr == nil {
		absRoot = resolved
	}
	rootTarget := req.ExecutionTarget
	rootTarget.Location = absRoot

	excludes := normalizeExcludeGlobs(req.ExcludeGlobs)
	start := time.Now()
	logger.Info("discovery: recursive walk starting",
		zap.String("root", absRoot),
		zap.Int("max_depth", req.MaxDepth),
		zap.Strings("exclude_patterns", excludes))

	seen := map[string]sdk.Subproject{}
	prunedAt := map[string]map[sdk.PackageManager]struct{}{}
	var dirsVisited, dirsSkippedBuiltin, dirsSkippedExclude, prunedCount int

	_ = filepath.WalkDir(absRoot, func(currentPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			logger.Warn("discovery: skipping unreadable path", zap.String("path", currentPath), zap.Error(walkErr))
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil //nolint:nilerr // best-effort walk: degrade and continue
		}
		if !entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(absRoot, currentPath)
		if relErr != nil {
			return nil //nolint:nilerr // best-effort walk
		}
		rel = filepath.ToSlash(rel)
		if rel != "." {
			if shouldSkipDiscoveryDir(entry.Name(), currentPath) {
				dirsSkippedBuiltin++
				return filepath.SkipDir
			}
			if pattern, matched := matchExcludeGlob(excludes, rel, entry.Name()); matched {
				dirsSkippedExclude++
				logger.Debug("discovery: excluded directory",
					zap.String("path", rel),
					zap.String("pattern", pattern))
				return filepath.SkipDir
			}
		}
		dirsVisited++

		for _, subproject := range plannedSubprojectsForPath(registryValue, rootTarget, currentPath, req.DetectorFilter, req.EcosystemFilter) {
			manager := subproject.PrimaryPackageManager()
			if ancestor, pruned := ancestorWithMultiModuleManager(prunedAt, rel, manager); pruned {
				prunedCount++
				logger.Debug("discovery: pruned nested subproject covered by ancestor",
					zap.String("path", subproject.RelativePath),
					zap.String("package_manager", manager.Name()),
					zap.String("ancestor", ancestor))
				continue
			}
			seen[subprojectDedupKey(subproject)] = subproject
			logger.Debug("discovery: planned subproject",
				zap.String("path", subproject.RelativePath),
				zap.String("package_manager", manager.Name()),
				zap.Strings("detectors", subproject.PlannedDetectors))
		}
		recordMultiModuleManagers(prunedAt, rel, currentPath)

		// Depth is only cut after the directory itself was inspected, so a
		// manifest at exactly MaxDepth is still discovered.
		if req.MaxDepth > 0 && discoveryDepth(rel) >= req.MaxDepth {
			return filepath.SkipDir
		}
		return nil
	})

	logger.Info("discovery: recursive walk complete",
		zap.String("root", absRoot),
		zap.Int("dirs_visited", dirsVisited),
		zap.Int("dirs_skipped_builtin", dirsSkippedBuiltin),
		zap.Int("dirs_skipped_exclude", dirsSkippedExclude),
		zap.Int("subprojects", len(seen)),
		zap.Int("pruned", prunedCount),
		zap.Duration("duration", time.Since(start)))

	if len(seen) == 0 {
		return nil, noSubprojectsError(req)
	}
	subprojects := make([]sdk.Subproject, 0, len(seen))
	for _, subproject := range seen {
		subprojects = append(subprojects, subproject)
	}
	sortSubprojects(subprojects)
	return subprojects, nil
}

// shouldSkipDiscoveryDir reports whether discovery must not descend into a
// directory: dot-directories, the built-in skip list, and non-hidden Python
// virtualenvs (identified by a pyvenv.cfg file).
func shouldSkipDiscoveryDir(name, dir string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	if _, ok := defaultDiscoverySkipDirs[name]; ok {
		return true
	}
	if info, err := os.Stat(filepath.Join(dir, "pyvenv.cfg")); err == nil && !info.IsDir() {
		return true
	}
	return false
}

// discoveryDepth returns the directory depth of a root-relative slash path:
// the root itself is depth 0, a direct child is depth 1.
func discoveryDepth(rel string) int {
	if rel == "" || rel == "." {
		return 0
	}
	return strings.Count(rel, "/") + 1
}

// normalizeExcludeGlobs canonicalizes user exclude patterns to slash form
// without surrounding slashes, dropping empties.
func normalizeExcludeGlobs(patterns []string) []string {
	normalized := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.Trim(strings.TrimSpace(strings.ReplaceAll(pattern, "\\", "/")), "/")
		if pattern == "" {
			continue
		}
		normalized = append(normalized, pattern)
	}
	return normalized
}

// matchExcludeGlob reports whether a directory matches an exclude pattern.
// Patterns containing a slash match against the root-relative path; patterns
// without one match against the directory basename at any depth. Patterns were
// syntax-checked during config validation, so match errors are ignored.
func matchExcludeGlob(patterns []string, rel, name string) (string, bool) {
	for _, pattern := range patterns {
		candidate := name
		if strings.Contains(pattern, "/") {
			candidate = rel
		}
		if matched, _ := path.Match(pattern, candidate); matched {
			return pattern, true
		}
	}
	return "", false
}

// ancestorWithMultiModuleManager reports whether an ancestor directory of rel
// already detected the given package manager and that manager natively expands
// nested modules; such nested subprojects resolve through the ancestor.
// Merged subprojects share one planned detector chain, so the primary manager
// decides for the whole subproject.
func ancestorWithMultiModuleManager(prunedAt map[string]map[sdk.PackageManager]struct{}, rel string, manager sdk.PackageManager) (string, bool) {
	if _, ok := nativeMultiModulePackageManagers[manager]; !ok {
		return "", false
	}
	for _, ancestor := range ancestorRelPaths(rel) {
		if managers, ok := prunedAt[ancestor]; ok {
			if _, ok := managers[manager]; ok {
				return ancestor, true
			}
		}
	}
	return "", false
}

// ancestorRelPaths returns the root-relative paths of every ancestor of rel,
// nearest the root first: "a/b/c" yields ".", "a", "a/b".
func ancestorRelPaths(rel string) []string {
	if rel == "" || rel == "." {
		return nil
	}
	segments := strings.Split(rel, "/")
	ancestors := make([]string, 0, len(segments))
	ancestors = append(ancestors, ".")
	for i := 1; i < len(segments); i++ {
		ancestors = append(ancestors, strings.Join(segments[:i], "/"))
	}
	return ancestors
}

// recordMultiModuleManagers remembers which workspace-expanding package
// managers have manifest evidence in dir so descendants can be pruned.
func recordMultiModuleManagers(prunedAt map[string]map[sdk.PackageManager]struct{}, rel, dir string) {
	for _, manager := range detectPackageManagers(dir) {
		if _, ok := nativeMultiModulePackageManagers[manager]; !ok {
			continue
		}
		managers, ok := prunedAt[rel]
		if !ok {
			managers = map[sdk.PackageManager]struct{}{}
			prunedAt[rel] = managers
		}
		managers[manager] = struct{}{}
	}
}
