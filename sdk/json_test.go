package sdk

import (
	"encoding/json"
	"testing"
)

func TestGraphJSONRoundTrip(t *testing.T) {
	graph := New()
	app := NewDependencyRefWithID("app@1.0.0", "app", "1.0.0")
	dep := NewDependencyRefWithID("dep@2.0.0", "dep", "2.0.0")
	if err := graph.AddNode(app); err != nil {
		t.Fatalf("AddNode(app): %v", err)
	}
	if err := graph.AddNode(dep); err != nil {
		t.Fatalf("AddNode(dep): %v", err)
	}
	if err := graph.AddEdge(app.ID, dep.ID); err != nil {
		t.Fatalf("AddEdge(): %v", err)
	}

	data, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}

	var decoded Graph
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}
	if decoded.Size() != 2 {
		t.Fatalf("decoded graph size = %d, want 2", decoded.Size())
	}
	deps, err := decoded.DirectDependencies(app.ID)
	if err != nil {
		t.Fatalf("DirectDependencies(): %v", err)
	}
	if len(deps) != 1 || deps[0].ID != dep.ID {
		t.Fatalf("decoded dependencies = %#v, want %q", deps, dep.ID)
	}
}
