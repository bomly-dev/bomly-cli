package output

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

// Every depends_on ID must name a record the same document defines.
//
// A workspace path runs module -> child manifest -> child module, and
// manifest nodes are deliberately not listed: they are what the listing is
// about. Publishing the manifest's ID anyway left a reference no consumer
// could resolve, and dropping it severed the workspace instead. The hop is
// stepped through, so the relationship survives in IDs the document defines.
func TestDependenciesFromGraphResolveThroughStructuralNodes(t *testing.T) {
	g := sdk.New()
	root := testnodes.Module("package.json", "workspace-root", "1.0.0")
	childManifest := testnodes.Manifest("packages/web/package.json", sdk.ManifestKindPackageJSON)
	child := testnodes.ModuleFrom("packages/web/package.json", sdk.Coordinates{
		Ecosystem: "npm", Name: "web", Version: "1.0.0",
	})
	leaf := testnodes.Dep(sdk.Coordinates{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	for _, node := range []sdk.GraphNode{root, childManifest, child, leaf} {
		if _, err := g.InsertNode(node); err != nil {
			t.Fatalf("InsertNode(%q): %v", node.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{
		{root.NodeID(), childManifest.NodeID()},
		{childManifest.NodeID(), child.NodeID()},
		{child.NodeID(), leaf.NodeID()},
	} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("AddEdge(%q -> %q): %v", edge[0], edge[1], err)
		}
	}

	entries := DependenciesFromGraph(g, nil)
	byID := make(map[string]ScanDependency, len(entries))
	for _, entry := range entries {
		byID[entry.ID] = entry
	}
	if _, listed := byID[childManifest.NodeID()]; listed {
		t.Fatalf("the manifest is listed as a dependency record; it is what the listing is about")
	}

	// No dangling reference anywhere in the document.
	for _, entry := range entries {
		for _, ref := range entry.DependsOn {
			if _, ok := byID[ref]; !ok {
				t.Fatalf("%q depends_on %q, which no record defines", entry.ID, ref)
			}
		}
	}

	// And the workspace path survives the omitted hop.
	rootEntry, ok := byID[root.NodeID()]
	if !ok {
		t.Fatalf("the workspace root is missing from the listing")
	}
	if len(rootEntry.DependsOn) != 1 || rootEntry.DependsOn[0] != child.NodeID() {
		t.Fatalf("root depends_on = %v, want the child module %q reached through the manifest",
			rootEntry.DependsOn, child.NodeID())
	}
	childEntry := byID[child.NodeID()]
	if len(childEntry.DependsOn) != 1 || childEntry.DependsOn[0] != leaf.NodeID() {
		t.Fatalf("child module depends_on = %v, want %q", childEntry.DependsOn, leaf.NodeID())
	}
}
