package sdk

import "testing"

// TestMergeGraphUnionsLocationsAcrossEntries pins the multi-module regression:
// when two entry graphs hold distinct instances of the same node and only one
// carries manifest locations (a gradle `api` dependency appears in both the
// declaring subproject's graph and each consumer's, located only in the
// declaring copy), the merged graph must keep the union of locations
// regardless of merge order.
func TestMergeGraphUnionsLocationsAcrossEntries(t *testing.T) {
	located := PackageLocation{
		RealPath:   "lib/build.gradle",
		AccessPath: "lib/build.gradle",
		Position:   &SourcePosition{File: "lib/build.gradle", Line: 7},
	}
	newEntry := func(withLocation bool) *Graph {
		g := New()
		dep := Dependency{Coordinates: Coordinates{Name: "commons-text", Version: "1.9", Ecosystem: EcosystemMaven}}
		if withLocation {
			dep.Locations = []PackageLocation{located}
		}
		if err := g.AddNode(NewDependencyWithID("commons-text@1.9", dep)); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		return g
	}

	for name, order := range map[string][]*Graph{
		"bare copy first":  {newEntry(false), newEntry(true)},
		"located first":    {newEntry(true), newEntry(false)},
		"duplicate copies": {newEntry(true), newEntry(true)},
	} {
		merged := New()
		for _, g := range order {
			if err := MergeGraph(merged, g); err != nil {
				t.Fatalf("%s: MergeGraph: %v", name, err)
			}
		}
		node, ok := merged.Node("commons-text@1.9")
		if !ok || node == nil {
			t.Fatalf("%s: merged node missing", name)
		}
		if len(node.Locations) != 1 {
			t.Fatalf("%s: locations = %+v, want exactly one", name, node.Locations)
		}
		loc := node.Locations[0]
		if loc.RealPath != located.RealPath || loc.Position == nil || *loc.Position != *located.Position {
			t.Fatalf("%s: location = %+v, want %+v", name, loc, located)
		}
	}
}

// TestConsolidatedGraphKeepsDeclaringModuleLocation drives the same union
// through the container-level view used by the scan/diff pipelines.
func TestConsolidatedGraphKeepsDeclaringModuleLocation(t *testing.T) {
	consumer := New()
	if err := consumer.AddNode(NewDependencyWithID("commons-text@1.9", Dependency{
		Coordinates: Coordinates{Name: "commons-text", Version: "1.9", Ecosystem: EcosystemMaven},
	})); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	declaring := New()
	if err := declaring.AddNode(NewDependencyWithID("commons-text@1.9", Dependency{
		Coordinates: Coordinates{Name: "commons-text", Version: "1.9", Ecosystem: EcosystemMaven},
		Locations: []PackageLocation{{
			RealPath: "lib/build.gradle",
			Position: &SourcePosition{File: "lib/build.gradle", Line: 7},
		}},
	})); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	container := &GraphContainer{Entries: []GraphEntry{
		{Graph: consumer, Manifest: ManifestMetadata{Path: "app/build.gradle"}},
		{Graph: declaring, Manifest: ManifestMetadata{Path: "lib/build.gradle"}},
	}}
	merged, err := container.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph: %v", err)
	}
	node, ok := merged.Node("commons-text@1.9")
	if !ok || node == nil {
		t.Fatal("merged node missing")
	}
	if len(node.Locations) != 1 || node.Locations[0].RealPath != "lib/build.gradle" {
		t.Fatalf("locations = %+v, want the declaring module location", node.Locations)
	}
}
