package jsreach

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

// discoverProjectRoots returns the npm project roots (directories that
// contain a package.json) derivable from the request. The same three
// sources govulncheck uses for go modules apply here, in priority
// order:
//
//  1. Each npm package's PackageLocation.RealPath: walk upward to the
//     nearest directory containing a package.json that ALSO has a
//     lockfile or a top-level "name" / "main" / "exports". This filters
//     out package.json files inside nested node_modules.
//  2. Each ConsolidatedManifest's manifest path when the request
//     surface ever exposes that (not currently part of AnalyzeRequest;
//     kept here as a future extension hook).
//  3. The request's ProjectPath / ExecutionTarget.Location, when it
//     itself contains a package.json.
//
// Paths are normalized with filepath.Clean. Duplicates are removed and
// results are sorted for deterministic ordering.
func discoverProjectRoots(req model.AnalyzeRequest) []string {
	seen := make(map[string]struct{})
	roots := make([]string, 0)

	add := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return
		}
		clean := filepath.Clean(dir)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		roots = append(roots, clean)
	}

	if req.Graph != nil {
		for _, pkg := range req.Graph.Packages() {
			if pkg == nil || !isNPMPackage(pkg) {
				continue
			}
			for _, loc := range pkg.Locations {
				if loc.RealPath == "" {
					continue
				}
				if root := findPackageJSONRoot(loc.RealPath); root != "" {
					add(root)
				}
			}
		}
	}

	for _, candidate := range []string{req.ProjectPath, req.ExecutionTarget.Location} {
		if candidate == "" {
			continue
		}
		if root := findPackageJSONRoot(candidate); root != "" {
			add(root)
		}
	}

	sort.Strings(roots)
	return roots
}

// findPackageJSONRoot walks upward from start until it finds a
// directory whose package.json looks like an application root (i.e.
// not a package.json that lives inside node_modules — those describe
// individual packages, not project roots). Returns "" when none is
// found before reaching the filesystem root.
//
// We deliberately accept a package.json with no "main" / "module" /
// "exports" / "bin" — entry-point discovery handles the
// implicit-index.js fallback.
func findPackageJSONRoot(start string) string {
	dir := start
	info, err := os.Stat(dir)
	if err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		if dir == "" {
			return ""
		}
		candidate := filepath.Join(dir, "package.json")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			if !isInsideNodeModules(dir) {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// isInsideNodeModules reports whether the given directory is itself
// inside a node_modules tree. The npm publish-time package.json files
// installed under node_modules look identical to project roots; we
// must skip them to avoid analysing a dependency as if it were the
// application.
func isInsideNodeModules(dir string) bool {
	normalized := filepath.ToSlash(dir)
	return strings.Contains(normalized, "/node_modules/") || strings.HasSuffix(normalized, "/node_modules")
}

// isNPMPackage reports whether pkg's ecosystem or build system
// identifies it as an npm package. Mirrors govulncheck.isGoPackage.
func isNPMPackage(pkg *model.Package) bool {
	if pkg == nil {
		return false
	}
	if strings.EqualFold(pkg.Ecosystem, string(model.EcosystemNPM)) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(pkg.BuildSystem)) {
	case "npm", "pnpm", "yarn":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(pkg.Language)) {
	case "javascript", "typescript":
		return true
	}
	return false
}
