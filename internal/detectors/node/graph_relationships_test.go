package node

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

func TestAttachUnknownComponentsMarksOnlyComponentRoots(t *testing.T) {
	graph := sdk.New()
	root := sdk.NewDependencyNode("app", sdk.DependencyNode{Coordinates: sdk.Coordinates{Name: "app", Type: sdk.PackageTypeApplication}})
	direct := sdk.NewDependencyNode("direct", sdk.DependencyNode{Coordinates: sdk.Coordinates{Name: "direct"}})
	orphan := sdk.NewDependencyNode("orphan", sdk.DependencyNode{Coordinates: sdk.Coordinates{Name: "orphan"}})
	child := sdk.NewDependencyNode("child", sdk.DependencyNode{Coordinates: sdk.Coordinates{Name: "child"}})
	for _, dep := range []*sdk.DependencyNode{root, direct, orphan, child} {
		if err := graph.AddNode(dep); err != nil {
			t.Fatal(err)
		}
	}
	if err := graph.AddEdge(root.NodeID(), direct.ID); err != nil {
		t.Fatal(err)
	}
	if err := graph.AddEdge(orphan.ID, child.NodeID()); err != nil {
		t.Fatal(err)
	}

	components, err := AttachUnknownComponents(graph, root.NodeID(), nil, "test", "package-lock.json")
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
	paths, err := graph.CollectPathsTo(child.NodeID())
	if err != nil || len(paths) != 1 {
		t.Fatalf("CollectPathsTo() paths=%d err=%v", len(paths), err)
	}
	if got := sdk.RelationshipForPath(paths[0].Nodes); got != sdk.DependencyRelationshipTransitive {
		t.Fatalf("child relationship = %q, want transitive", got)
	}
}

func TestAttachUnknownComponentsRetainsDisconnectedCycle(t *testing.T) {
	graph := sdk.New()
	root := sdk.NewDependencyNode("app", sdk.DependencyNode{Coordinates: sdk.Coordinates{Name: "app", Type: sdk.PackageTypeApplication}})
	a := sdk.NewDependencyRefWithID("a", "a", "1")
	b := sdk.NewDependencyRefWithID("b", "b", "1")
	for _, dependency := range []*sdk.DependencyNode{root, a, b} {
		if err := graph.AddNode(dependency); err != nil {
			t.Fatal(err)
		}
	}
	if err := graph.AddEdge(a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := graph.AddEdge(b.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	components, err := AttachUnknownComponents(graph, root.NodeID(), nil, "test", "yarn.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 || components[0].Size != 2 {
		t.Fatalf("components = %#v", components)
	}
	if components[0].RootID != "a" || a.Relationship != sdk.DependencyRelationshipUnknown {
		t.Fatalf("cycle root = %#v, relationship=%q", components[0], a.Relationship)
	}
}
