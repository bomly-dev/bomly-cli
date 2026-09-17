package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestRebaseGraphLocations_PrefixesSubprojectPath(t *testing.T) {
	g := model.New()
	dep := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{Name: "lodash", Version: "4.17.21"},
		Locations: []model.PackageLocation{{
			RealPath:   "package-lock.json",
			AccessPath: "package-lock.json",
			Position:   &model.SourcePosition{File: "package-lock.json", Line: 8},
		}},
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	rebaseGraphLocations(g, "apps/web")

	node, ok := testnodes.FindDep(g, "lodash@4.17.21")
	if !ok {
		t.Fatal("expected lodash node")
	}
	loc := node.Locations[0]
	if loc.RealPath != "apps/web/package-lock.json" || loc.AccessPath != "apps/web/package-lock.json" {
		t.Fatalf("rebased paths = %q / %q, want apps/web/package-lock.json", loc.RealPath, loc.AccessPath)
	}
	if loc.Position == nil || loc.Position.File != "apps/web/package-lock.json" || loc.Position.Line != 8 {
		t.Fatalf("rebased position = %#v, want apps/web/package-lock.json line 8", loc.Position)
	}
}

func TestRebaseGraphLocations_RootIsNoOp(t *testing.T) {
	for _, rel := range []string{".", "", "  "} {
		g := model.New()
		dep := testnodes.DepFrom(model.DependencyNode{
			Coordinates: model.Coordinates{Name: "lodash", Version: "4.17.21"},
			Locations:   []model.PackageLocation{{RealPath: "package-lock.json", Position: &model.SourcePosition{File: "package-lock.json", Line: 8}}},
		})
		if err := g.AddNode(dep); err != nil {
			t.Fatalf("AddNode: %v", err)
		}

		rebaseGraphLocations(g, rel)

		node, _ := testnodes.FindDep(g, "lodash@4.17.21")
		if node.Locations[0].RealPath != "package-lock.json" || node.Locations[0].Position.File != "package-lock.json" {
			t.Fatalf("RelativePath %q must be a no-op, got %#v", rel, node.Locations[0])
		}
	}
}

func TestRebaseGraphLocations_SkipsAbsoluteAndAlreadyPrefixed(t *testing.T) {
	g := model.New()
	dep := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{Name: "pkg", Version: "1.0.0"},
		Locations: []model.PackageLocation{
			{RealPath: "/abs/pom.xml", Position: &model.SourcePosition{File: "/abs/pom.xml", Line: 1}},
			{RealPath: "apps/web/already.json", Position: &model.SourcePosition{File: "apps/web/already.json", Line: 2}},
		},
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	rebaseGraphLocations(g, "apps/web")

	node, _ := testnodes.FindDep(g, "pkg@1.0.0")
	if got := node.Locations[0].RealPath; got != "/abs/pom.xml" {
		t.Fatalf("absolute path = %q, want untouched", got)
	}
	if got := node.Locations[1].RealPath; got != "apps/web/already.json" {
		t.Fatalf("already-prefixed path = %q, want untouched (no double prefix)", got)
	}
}

// TestConsolidateGraphs_RebasesCoreDetectorLocations proves the core-gated
// rebasing fires through the real consolidation entry point.
func TestConsolidateGraphs_RebasesCoreDetectorLocations(t *testing.T) {
	g := model.New()
	dep := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
		Locations:   []model.PackageLocation{{RealPath: "package-lock.json", Position: &model.SourcePosition{File: "package-lock.json", Line: 8}}},
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	consolidated, err := ConsolidateGraphs([]plugin.DetectionResult{{
		SubprojectInfo: plugin.Subproject{
			ExecutionTarget:         plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo"},
			RelativePath:            "apps/web",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       plugin.CoreOrigin,
		Technique:    plugin.BuildToolTechnique,
		Graphs:       model.SingleGraphContainer(g, model.ManifestMetadata{Path: "apps/web/package-lock.json", Kind: "package-lock.json"}),
	}})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}

	graph, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	var node *model.DependencyNode
	for _, n := range graph.DependencyNodes() {
		if n != nil && n.Name == "lodash" {
			node = n
			break
		}
	}
	if node == nil {
		t.Fatalf("expected lodash node, got %v", graph.DependencyNodes())
	}
	if len(node.Locations) == 0 || node.Locations[0].Position == nil || node.Locations[0].Position.File != "apps/web/package-lock.json" {
		t.Fatalf("consolidated location = %#v, want apps/web/package-lock.json", node.Locations)
	}
}

// TestRebaseGraphLocations_MovesModuleRootIntoRepositoryCoordinates covers the
// join key ADR-0037 defines: a detector names its own working directory ".",
// and two subprojects both claiming "." cannot be told apart.
func TestRebaseGraphLocations_MovesModuleRootIntoRepositoryCoordinates(t *testing.T) {
	g := model.New()
	dep := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{Name: "lodash", Version: "4.17.21"},
		Locations: []model.PackageLocation{
			{RealPath: "package-lock.json", ModuleRoot: "."},
			{RealPath: "packages/lib/package.json", ModuleRoot: "packages/lib"},
			{RealPath: "vendored/pom.xml"},
		},
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	rebaseGraphLocations(g, "apps/web")

	node, ok := testnodes.FindDep(g, "lodash@4.17.21")
	if !ok {
		t.Fatal("expected lodash node")
	}
	if got := node.Locations[0].ModuleRoot; got != "apps/web" {
		t.Fatalf("subproject root module root = %q, want apps/web", got)
	}
	if got := node.Locations[1].ModuleRoot; got != "apps/web/packages/lib" {
		t.Fatalf("nested module root = %q, want apps/web/packages/lib", got)
	}
	if got := node.Locations[2].ModuleRoot; got != "" {
		t.Fatalf("unattributed module root = %q, want it left empty", got)
	}
}
