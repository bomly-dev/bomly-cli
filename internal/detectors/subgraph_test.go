package detectors

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func subgraphFixture(t *testing.T, edges [][2]string) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	added := map[string]struct{}{}
	addNode := func(id string) {
		if _, ok := added[id]; ok {
			return
		}
		added[id] = struct{}{}
		if err := g.AddNode(sdk.NewDependencyWithID(id, sdk.Dependency{Coordinates: sdk.Coordinates{Name: id}})); err != nil {
			t.Fatalf("add node %q: %v", id, err)
		}
	}
	for _, edge := range edges {
		addNode(edge[0])
		addNode(edge[1])
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %v: %v", edge, err)
		}
	}
	return g
}

func TestSubgraphFromExtractsReachableSubtree(t *testing.T) {
	g := subgraphFixture(t, [][2]string{
		{"root", "a"}, {"a", "shared"},
		{"module", "b"}, {"b", "shared"}, // diamond: shared reachable twice
		{"unrelated", "c"},
	})

	sub, err := SubgraphFrom(g, "module")
	if err != nil {
		t.Fatalf("SubgraphFrom() error = %v", err)
	}
	for _, want := range []string{"module", "b", "shared"} {
		if _, ok := sub.Node(want); !ok {
			t.Fatalf("expected node %q in subgraph", want)
		}
	}
	for _, forbidden := range []string{"root", "a", "unrelated", "c"} {
		if _, ok := sub.Node(forbidden); ok {
			t.Fatalf("unexpected node %q in subgraph", forbidden)
		}
	}
	if sub.Size() != 3 {
		t.Fatalf("expected 3 nodes, got %d", sub.Size())
	}
	deps, err := sub.DirectDependencies("b")
	if err != nil || len(deps) != 1 || deps[0].ID != "shared" {
		t.Fatalf("expected b -> shared edge, got %v (%v)", deps, err)
	}
}

func TestSubgraphFromHandlesCycles(t *testing.T) {
	g := subgraphFixture(t, [][2]string{
		{"root", "a"}, {"a", "b"}, {"b", "a"},
	})
	sub, err := SubgraphFrom(g, "root")
	if err != nil {
		t.Fatalf("SubgraphFrom() error = %v", err)
	}
	if sub.Size() != 3 {
		t.Fatalf("expected cycle nodes preserved, got %d nodes", sub.Size())
	}
}

func TestSubgraphFromMissingRoot(t *testing.T) {
	g := subgraphFixture(t, [][2]string{{"root", "a"}})
	if _, err := SubgraphFrom(g, "nope"); err == nil {
		t.Fatal("expected error for missing root")
	}
	if _, err := SubgraphFrom(nil, "root"); err == nil {
		t.Fatal("expected error for nil graph")
	}
}
