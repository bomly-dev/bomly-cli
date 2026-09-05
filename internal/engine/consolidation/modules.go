package consolidation

import (
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/detectorkit"
)

// rebaseModuleDeclaringPaths rewrites each module's declaring manifest path so
// it is relative to the repository root, re-minting the module's identity.
//
// A module's ID is "module:<declaring path>#<purl>", and a detector writes the
// path in its own working directory's coordinate space: a project discovered
// at "apps/web" declares its module from "package.json", not
// "apps/web/package.json". With --recursive that is an identity collision
// waiting to happen -- two nested projects that share a package name mint the
// same "module:package.json#pkg:npm/app@1.0.0", and because insertion folds by
// identity, the independent roots merge into one node carrying both projects'
// dependency edges. Whole-scan output, explain, and the TUI then cannot tell
// the projects apart.
//
// Rebasing here rather than in each detector is deliberate: this is the stage
// that already knows the subproject's relative path and already rebases
// manifest paths and locations with it. A detector cannot -- it does not know
// where it was mounted.
//
// The identity changes, so the node is re-minted through PromoteToModule,
// which re-points every edge and preserves edge kinds. IDs are collected
// before any promotion because promoting mutates the graph being walked.
func rebaseModuleDeclaringPaths(g *sdk.Graph, relativePath string) error {
	rel := strings.Trim(strings.TrimSpace(toSlashPath(relativePath)), "/")
	if g == nil || rel == "" || rel == "." {
		return nil
	}

	type promotion struct {
		nodeID string
		path   string
	}
	modules := g.ModuleNodes()
	pending := make([]promotion, 0, len(modules))
	for _, module := range modules {
		if module == nil {
			continue
		}
		rebased := rebaseLocationPath(module.DeclaringManifestPath, rel)
		if rebased == module.DeclaringManifestPath {
			continue
		}
		pending = append(pending, promotion{nodeID: module.NodeID(), path: rebased})
	}
	for _, item := range pending {
		if _, err := detectorkit.PromoteToModule(g, item.nodeID, item.path); err != nil {
			return fmt.Errorf("rebase module %q onto %q: %w", item.nodeID, item.path, err)
		}
	}
	return nil
}
