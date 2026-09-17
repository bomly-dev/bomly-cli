package node

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
)

func TestAttachUnknownComponentsMarksOnlyComponentRoots(t *testing.T) {
	graph := model.New()
	root := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "app", Type: model.PackageTypeApplication}})
	direct := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "direct"}})
	orphan := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "orphan"}})
	child := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "child"}})
	for _, dep := range []*model.DependencyNode{root, direct, orphan, child} {
		if err := graph.AddNode(dep); err != nil {
			t.Fatal(err)
		}
	}
	if err := graph.AddEdge(root.NodeID(), direct.NodeID()); err != nil {
		t.Fatal(err)
	}
	if err := graph.AddEdge(orphan.NodeID(), child.NodeID()); err != nil {
		t.Fatal(err)
	}

	components, err := AttachUnknownComponents(graph, root.NodeID(), nil, "test", "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 || components[0].RootID != orphan.NodeID() || components[0].Size != 2 {
		t.Fatalf("components = %#v", components)
	}
	if orphan.Relationship != model.DependencyRelationshipUnknown {
		t.Fatalf("orphan relationship = %q", orphan.Relationship)
	}
	if child.Relationship != "" {
		t.Fatalf("child relationship = %q, want derived transitive", child.Relationship)
	}
	paths, err := graph.CollectPathsTo(child.NodeID())
	if err != nil || len(paths) != 1 {
		t.Fatalf("CollectPathsTo() paths=%d err=%v", len(paths), err)
	}
	if got := model.RelationshipForPath(paths[0].Nodes); got != model.DependencyRelationshipTransitive {
		t.Fatalf("child relationship = %q, want transitive", got)
	}
}

func TestAttachUnknownComponentsRetainsDisconnectedCycle(t *testing.T) {
	graph := model.New()
	root := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "app", Type: model.PackageTypeApplication}})
	a := testnodes.Ref("a", "1")
	b := testnodes.Ref("b", "1")
	for _, dependency := range []*model.DependencyNode{root, a, b} {
		if err := graph.AddNode(dependency); err != nil {
			t.Fatal(err)
		}
	}
	if err := graph.AddEdge(a.NodeID(), b.NodeID()); err != nil {
		t.Fatal(err)
	}
	if err := graph.AddEdge(b.NodeID(), a.NodeID()); err != nil {
		t.Fatal(err)
	}
	components, err := AttachUnknownComponents(graph, root.NodeID(), nil, "test", "yarn.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 || components[0].Size != 2 {
		t.Fatalf("components = %#v", components)
	}
	if components[0].RootID != a.NodeID() || a.Relationship != model.DependencyRelationshipUnknown {
		t.Fatalf("cycle root = %#v, relationship=%q", components[0], a.Relationship)
	}
}
