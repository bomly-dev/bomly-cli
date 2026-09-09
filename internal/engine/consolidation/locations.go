package consolidation

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// rebaseGraphLocations rewrites subproject-relative PackageLocation paths so
// they are relative to the repository root by prefixing the subproject's
// RelativePath.
//
// Detectors emit location paths in the coordinate space of their own working
// directory — a subproject discovered at "apps/web" reports a lockfile location
// of "package-lock.json", not "apps/web/package-lock.json". Diff-aware SARIF and
// GitHub code scanning expect repository-root-relative paths, so the prefix has
// to be reattached during consolidation (the same stage that already rebases
// manifest paths via normalizeNativeManifestPath).
//
// This is a deliberate no-op for root-level subprojects (RelativePath "." or
// ""), which is every subproject today because discovery does not recurse into
// subdirectories. It exists so a future recursive scan mode reports correct
// locations without revisiting every detector.
func rebaseGraphLocations(g *sdk.Graph, relativePath string) {
	rel := strings.Trim(strings.TrimSpace(toSlashPath(relativePath)), "/")
	if g == nil || rel == "" || rel == "." {
		return
	}
	// Every node kind that carries locations, not just dependencies. A
	// promoted module keeps the locations of the dependency node it replaced,
	// so restricting the walk left a subproject's module reporting "pom.xml"
	// where the repository holds "apps/service/pom.xml" -- and
	// DependenciesFromGraph publishes module locations in scan JSON, so the
	// stale path reached the output.
	g.WalkNodes(func(node sdk.GraphNode) bool {
		for _, location := range mutableLocations(node) {
			location.RealPath = rebaseLocationPath(location.RealPath, rel)
			location.AccessPath = rebaseLocationPath(location.AccessPath, rel)
			location.ModuleRoot = rebaseModuleRoot(location.ModuleRoot, rel)
			if location.Position != nil {
				location.Position.File = rebaseLocationPath(location.Position.File, rel)
			}
		}
		return true
	})
}

// mutableLocations returns pointers into the node's own location slice, so a
// rewrite lands on the node rather than on a copy. A manifest node carries no
// locations: its path is its identity, and normalizeNativeManifestPath rebases
// that.
func mutableLocations(node sdk.GraphNode) []*sdk.PackageLocation {
	var locations []sdk.PackageLocation
	switch typed := node.(type) {
	case *sdk.DependencyNode:
		if typed == nil {
			return nil
		}
		locations = typed.Locations
	case *sdk.ModuleNode:
		if typed == nil {
			return nil
		}
		locations = typed.Locations
	default:
		return nil
	}
	out := make([]*sdk.PackageLocation, 0, len(locations))
	for i := range locations {
		out = append(out, &locations[i])
	}
	return out
}

// rebaseLocationPath prefixes rel onto a subproject-relative path. Empty,
// absolute, and already-prefixed paths are returned unchanged so the rewrite is
// idempotent and never corrupts a path a detector emitted repo-relative.
func rebaseLocationPath(p, rel string) string {
	trimmed := strings.TrimSpace(toSlashPath(p))
	if trimmed == "" {
		return p
	}
	if strings.HasPrefix(trimmed, "/") {
		return trimmed
	}
	if trimmed == rel || strings.HasPrefix(trimmed, rel+"/") {
		return trimmed
	}
	return rel + "/" + trimmed
}

// rebaseModuleRoot moves a location's module root into repository-root
// coordinates alongside its paths.
//
// A detector names the module it resolved in its own working directory, so
// every subproject calls its own root "." -- and left alone, two subprojects
// scanned recursively would both claim ".", making the module root useless as
// the join key ADR-0037 defines it to be. An unattributed root stays empty:
// the prefix would turn "the producer did not attribute this site" into a
// claim about a directory.
func rebaseModuleRoot(moduleRoot, rel string) string {
	trimmed := strings.TrimSpace(toSlashPath(moduleRoot))
	if trimmed == "" {
		return moduleRoot
	}
	if trimmed == "." {
		return rel
	}
	return rebaseLocationPath(trimmed, rel)
}

func toSlashPath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}
