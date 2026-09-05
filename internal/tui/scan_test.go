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

// Explain must keep the project's own module in view.
//
// A normal graph's root is a module node, and for a transitive target it is
// not a direct parent of that target — so the dependency-only walk skipped it
// entirely: the component list lost the project row, and the header counted
// "Roots: 0" for a scan that plainly has one. Nested workspace modules were
// hidden the same way.
func TestExplainRelationshipsCountModuleRoots(t *testing.T) {
	g := sdk.New()
	root := testnodes.Module("package.json", "app", "1.0.0")
	direct := testnodes.Dep(sdk.Coordinates{Ecosystem: "npm", Name: "react", Version: "18.2.0"})
	transitive := testnodes.Dep(sdk.Coordinates{Ecosystem: "npm", Name: "loose-envify", Version: "1.4.0"})
	for _, node := range []sdk.GraphNode{root, direct, transitive} {
		if _, err := g.InsertNode(node); err != nil {
			t.Fatalf("InsertNode(%q): %v", node.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{
		{root.NodeID(), direct.NodeID()},
		{direct.NodeID(), transitive.NodeID()},
	} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("AddEdge: %v", err)
		}
	}

	// The target is transitive, so the module root is an ancestor rather than
	// a direct parent — the case the narrowing lost.
	labels, counts := explainRelationships(g, transitive.NodeID())
	if counts["root"] != 1 {
		t.Fatalf("root count = %d, want the project's module root counted; labels=%v", counts["root"], labels)
	}
	if got := labels[root.NodeID()]; got != "root" {
		t.Fatalf("module root labelled %q, want %q", got, "root")
	}
	if got := labels[direct.NodeID()]; got != "parent" {
		t.Fatalf("direct dependency labelled %q, want %q", got, "parent")
	}
	if got := labels[transitive.NodeID()]; got != "self" {
		t.Fatalf("target labelled %q, want %q", got, "self")
	}
}

// A non-root module is a directness parent, so its immediate packages are
// direct rather than transitive.
//
// A workspace module that another module depends on has an incoming edge, so
// a roots-only classifier never saw it and reported its direct dependencies
// as transitive — corrupting the relationship summary and every filter built
// on it. renderDirectDepsTable had already learned this; this classifier had
// not, which is why the rule now has one home.
func TestClassifyRelationshipsTreatsNonRootModulesAsParents(t *testing.T) {
	g := sdk.New()
	root := testnodes.Module("package.json", "workspace-root", "1.0.0")
	child := testnodes.ModuleFrom("packages/web/package.json", sdk.Coordinates{
		Ecosystem: "npm", Name: "web", Version: "1.0.0",
	})
	pkg := testnodes.Dep(sdk.Coordinates{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	for _, node := range []sdk.GraphNode{root, child, pkg} {
		if _, err := g.InsertNode(node); err != nil {
			t.Fatalf("InsertNode: %v", err)
		}
	}
	for _, edge := range [][2]string{{root.NodeID(), child.NodeID()}, {child.NodeID(), pkg.NodeID()}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("AddEdge: %v", err)
		}
	}

	classes := classifyRelationships(g)
	if got := classes[pkg.NodeID()]; got != "direct" {
		t.Fatalf("package under a non-root module classified %q, want %q", got, "direct")
	}
}

// The raw Relationships view must show module-to-package edges.
//
// A normal graph starts with a module node, so reading dependency nodes alone
// as parents omitted every edge out of it — for a project with only direct
// dependencies the view was empty while the count beside it was not.
func TestRelationshipRawLinesIncludeModuleEdges(t *testing.T) {
	g := sdk.New()
	root := testnodes.Module("package.json", "app", "1.0.0")
	pkg := testnodes.Dep(sdk.Coordinates{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	for _, node := range []sdk.GraphNode{root, pkg} {
		if _, err := g.InsertNode(node); err != nil {
			t.Fatalf("InsertNode: %v", err)
		}
	}
	if err := g.AddEdge(root.NodeID(), pkg.NodeID()); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}

	lines := relationshipRawLines(g)
	if len(lines) == 0 {
		t.Fatalf("the raw relationship view is empty for a graph with one module-to-package edge")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "lodash") {
		t.Fatalf("the module's edge to its package is missing:\n%s", joined)
	}
}
