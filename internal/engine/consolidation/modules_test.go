package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

// Two nested projects that share a package name must stay two nodes.
//
// A module's ID carries its declaring manifest path, and a detector writes
// that path relative to its own working directory, so both projects declare
// from "package.json" and mint the same ID. Insertion folds by identity, so
// without this rebase --recursive merged the two roots into one node holding
// both projects' dependency edges.
func TestRebaseModuleDeclaringPathsKeepsNestedProjectsApart(t *testing.T) {
	build := func(rel string) *sdk.Graph {
		g := sdk.New()
		module := testnodes.ModuleFrom("package.json", sdk.Coordinates{Ecosystem: "npm", Name: "app", Version: "1.0.0"})
		dep := testnodes.Dep(sdk.Coordinates{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
		for _, node := range []sdk.GraphNode{module, dep} {
			if _, err := g.InsertNode(node); err != nil {
				t.Fatalf("InsertNode: %v", err)
			}
		}
		if err := g.AddEdge(module.NodeID(), dep.NodeID()); err != nil {
			t.Fatalf("AddEdge: %v", err)
		}
		if err := rebaseModuleDeclaringPaths(g, rel); err != nil {
			t.Fatalf("rebaseModuleDeclaringPaths(%q): %v", rel, err)
		}
		return g
	}

	web := build("apps/web")
	api := build("apps/api")

	webModules := web.ModuleNodes()
	apiModules := api.ModuleNodes()
	if len(webModules) != 1 || len(apiModules) != 1 {
		t.Fatalf("module counts = %d and %d; want one each", len(webModules), len(apiModules))
	}
	if webModules[0].NodeID() == apiModules[0].NodeID() {
		t.Fatalf("both projects minted %q; nested projects must stay distinguishable", webModules[0].NodeID())
	}
	if got := webModules[0].DeclaringManifestPath; got != "apps/web/package.json" {
		t.Fatalf("web declaring path = %q, want %q", got, "apps/web/package.json")
	}

	// The rebase re-mints the node, so its edges must survive.
	deps, err := web.DirectDependencies(webModules[0].NodeID())
	if err != nil {
		t.Fatalf("DirectDependencies: %v", err)
	}
	if len(deps) != 1 || deps[0].NodeID() != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("module dependencies = %#v; want the lodash edge re-pointed at the new ID", deps)
	}
}

// A root-level subproject is unchanged: the paths are already repo-relative,
// and re-minting them would churn every ID in a non-recursive scan.
func TestRebaseModuleDeclaringPathsLeavesRootSubprojectsAlone(t *testing.T) {
	for _, rel := range []string{"", ".", "  "} {
		g := sdk.New()
		module := testnodes.ModuleFrom("package.json", sdk.Coordinates{Ecosystem: "npm", Name: "app", Version: "1.0.0"})
		if _, err := g.InsertNode(module); err != nil {
			t.Fatalf("InsertNode: %v", err)
		}
		before := module.NodeID()
		if err := rebaseModuleDeclaringPaths(g, rel); err != nil {
			t.Fatalf("rebaseModuleDeclaringPaths(%q): %v", rel, err)
		}
		modules := g.ModuleNodes()
		if len(modules) != 1 || modules[0].NodeID() != before {
			t.Fatalf("relative path %q re-minted %q; want it unchanged", rel, before)
		}
	}
}
