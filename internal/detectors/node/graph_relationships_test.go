package node

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestAttachUnknownComponentsMarksOnlyComponentRoots(t *testing.T) {
	graph := sdk.New()
	root := sdk.NewDependencyWithID("app", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "app", Type: sdk.PackageTypeApplication}})
	direct := sdk.NewDependencyWithID("direct", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "direct"}})
	orphan := sdk.NewDependencyWithID("orphan", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "orphan"}})
	child := sdk.NewDependencyWithID("child", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "child"}})
	for _, dep := range []*sdk.Dependency{root, direct, orphan, child} {
		if err := graph.AddNode(dep); err != nil {
			t.Fatal(err)
		}
	}
	if err := graph.AddEdge(root.ID, direct.ID); err != nil {
		t.Fatal(err)
	}
	if err := graph.AddEdge(orphan.ID, child.ID); err != nil {
		t.Fatal(err)
	}

	components, err := AttachUnknownComponents(graph, root.ID, nil, "test", "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 || components[0].RootID != orphan.ID || components[0].Size != 2 {
		t.Fatalf("components = %#v", components)
	}
	if orphan.Relationship != sdk.DependencyRelationshipUnknown {
		t.Fatalf("orphan relationship = %q", orphan.Relationship)
	}
	if child.Relationship != "" {
		t.Fatalf("child relationship = %q, want derived transitive", child.Relationship)
	}
	paths, err := graph.CollectPathsTo(child.ID)
	if err != nil || len(paths) != 1 {
		t.Fatalf("CollectPathsTo() paths=%d err=%v", len(paths), err)
	}
	if got := sdk.RelationshipForPath(paths[0].Nodes); got != sdk.DependencyRelationshipTransitive {
		t.Fatalf("child relationship = %q, want transitive", got)
	}
}
