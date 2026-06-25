package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestRebaseGraphLocations_PrefixesSubprojectPath(t *testing.T) {
	g := sdk.New()
	dep := sdk.NewDependencyWithID("lodash@4.17.21", sdk.Dependency{
		Coordinates: sdk.Coordinates{Name: "lodash", Version: "4.17.21"},
		Locations: []sdk.PackageLocation{{
			RealPath:   "package-lock.json",
			AccessPath: "package-lock.json",
			Position:   &sdk.SourcePosition{File: "package-lock.json", Line: 8},
		}},
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	rebaseGraphLocations(g, "apps/web")

	node, ok := g.Node("lodash@4.17.21")
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
		g := sdk.New()
		dep := sdk.NewDependencyWithID("lodash@4.17.21", sdk.Dependency{
			Coordinates: sdk.Coordinates{Name: "lodash", Version: "4.17.21"},
			Locations:   []sdk.PackageLocation{{RealPath: "package-lock.json", Position: &sdk.SourcePosition{File: "package-lock.json", Line: 8}}},
		})
		if err := g.AddNode(dep); err != nil {
			t.Fatalf("AddNode: %v", err)
		}

		rebaseGraphLocations(g, rel)

		node, _ := g.Node("lodash@4.17.21")
		if node.Locations[0].RealPath != "package-lock.json" || node.Locations[0].Position.File != "package-lock.json" {
			t.Fatalf("RelativePath %q must be a no-op, got %#v", rel, node.Locations[0])
		}
	}
}

func TestRebaseGraphLocations_SkipsAbsoluteAndAlreadyPrefixed(t *testing.T) {
	g := sdk.New()
	dep := sdk.NewDependencyWithID("pkg@1.0.0", sdk.Dependency{
		Coordinates: sdk.Coordinates{Name: "pkg", Version: "1.0.0"},
		Locations: []sdk.PackageLocation{
			{RealPath: "/abs/pom.xml", Position: &sdk.SourcePosition{File: "/abs/pom.xml", Line: 1}},
			{RealPath: "apps/web/already.json", Position: &sdk.SourcePosition{File: "apps/web/already.json", Line: 2}},
		},
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	rebaseGraphLocations(g, "apps/web")

	node, _ := g.Node("pkg@1.0.0")
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
	g := sdk.New()
	dep := sdk.NewDependency(sdk.Dependency{
		Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
		Locations:   []sdk.PackageLocation{{RealPath: "package-lock.json", Position: &sdk.SourcePosition{File: "package-lock.json", Line: 8}}},
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
			RelativePath:            "apps/web",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Technique:    sdk.BuildToolTechnique,
		Graphs:       sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "apps/web/package-lock.json", Kind: "package-lock.json"}),
	}})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}

	graph, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	var node *sdk.Dependency
	for _, n := range graph.Nodes() {
		if n != nil && n.Name == "lodash" {
			node = n
			break
		}
	}
	if node == nil {
		t.Fatalf("expected lodash node, got %v", graph.Nodes())
	}
	if len(node.Locations) == 0 || node.Locations[0].Position == nil || node.Locations[0].Position.File != "apps/web/package-lock.json" {
		t.Fatalf("consolidated location = %#v, want apps/web/package-lock.json", node.Locations)
	}
}
