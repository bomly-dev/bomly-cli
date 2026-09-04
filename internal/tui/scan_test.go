package tui

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

// A structural node's PURL column must carry a real package URL, or nothing.
//
// A module's NodeID is the "module:<path>#<purl>" grammar and a manifest has
// no package URL at all, but the row put NodeID in the field the details pane
// labels "PURL" -- so an interactive scan showed a value no consumer could
// parse, while scan JSON and both SBOM exports had it right.
func TestPackageRowPurlIsNeverAStructuralID(t *testing.T) {
	module := testnodes.Module("package.json", "app", "1.0.0")
	manifest := testnodes.Manifest("package.json", sdk.ManifestKindPackageJSON)
	dependency := testnodes.Dep(sdk.Coordinates{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})

	moduleRow := packageRowFromGraph(module, "root")
	if strings.HasPrefix(moduleRow.purl, "module:") {
		t.Fatalf("module row purl = %q; want the module's own package URL", moduleRow.purl)
	}
	if moduleRow.purl != module.PURL() {
		t.Fatalf("module row purl = %q, want %q", moduleRow.purl, module.PURL())
	}

	manifestRow := packageRowFromGraph(manifest, "manifest")
	if manifestRow.purl != "" {
		t.Fatalf("manifest row purl = %q; a manifest is a file and has no package URL", manifestRow.purl)
	}

	// A dependency's identity is its package URL, so it is unchanged.
	dependencyRow := packageRowFromGraph(dependency, "direct")
	if dependencyRow.purl != dependency.NodeID() {
		t.Fatalf("dependency row purl = %q, want its identity %q", dependencyRow.purl, dependency.NodeID())
	}
}
