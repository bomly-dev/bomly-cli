package consolidation

import (
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
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
	for _, pkg := range g.Nodes() {
		if pkg == nil {
			continue
		}
		for i := range pkg.Locations {
			pkg.Locations[i].RealPath = rebaseLocationPath(pkg.Locations[i].RealPath, rel)
			pkg.Locations[i].AccessPath = rebaseLocationPath(pkg.Locations[i].AccessPath, rel)
			if pos := pkg.Locations[i].Position; pos != nil {
				pos.File = rebaseLocationPath(pos.File, rel)
			}
		}
	}
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

func toSlashPath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}
