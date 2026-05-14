package govulncheck

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

// discoverModuleRoots returns the set of Go module roots derivable from
// the request. Three sources are considered, in priority order:
//
//  1. Each Go package's PackageLocation.RealPath: walk upward to the
//     nearest directory containing go.mod.
//  2. Each ConsolidatedManifest's ManifestMetadata.Path when its kind is
//     "go.mod" (not currently exposed on AnalyzeRequest, but kept here
//     as a future extension hook).
//  3. The request's ProjectPath / ExecutionTarget.Location, when it
//     itself contains a go.mod.
//
// Paths are normalized with filepath.Clean. Duplicates are removed and
// results are sorted for deterministic ordering.
func discoverModuleRoots(req model.AnalyzeRequest) []string {
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
			if pkg == nil || !isGoPackage(pkg) {
				continue
			}
			for _, loc := range pkg.Locations {
				if loc.RealPath == "" {
					continue
				}
				if root := findGoModRoot(loc.RealPath); root != "" {
					add(root)
				}
			}
		}
	}

	for _, candidate := range []string{req.ProjectPath, req.ExecutionTarget.Location} {
		if candidate == "" {
			continue
		}
		if root := findGoModRoot(candidate); root != "" {
			add(root)
		}
	}

	sort.Strings(roots)
	return roots
}

// findGoModRoot walks upward from start until it finds a directory
// containing go.mod, or returns "" when none is found before reaching
// the filesystem root.
func findGoModRoot(start string) string {
	dir := start
	info, err := os.Stat(dir)
	if err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		if dir == "" {
			return ""
		}
		candidate := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(candidate); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
