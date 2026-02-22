package sdk

import (
	"encoding/json"
	"testing"
)

func TestGraphJSONRoundTrip(t *testing.T) {
	graph := New()
	app := NewPackageRefWithID("app@1.0.0", "app", "1.0.0")
	dep := NewPackageRefWithID("dep@2.0.0", "dep", "2.0.0")
	if err := graph.AddPackage(app); err != nil {
		t.Fatalf("AddPackage(app): %v", err)
	}
	if err := graph.AddPackage(dep); err != nil {
		t.Fatalf("AddPackage(dep): %v", err)
	}
	if err := graph.AddDependency(app.ID, dep.ID); err != nil {
		t.Fatalf("AddDependency(): %v", err)
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
	deps, err := decoded.Dependencies(app.ID)
	if err != nil {
		t.Fatalf("Dependencies(): %v", err)
	}
	if len(deps) != 1 || deps[0].ID != dep.ID {
		t.Fatalf("decoded dependencies = %#v, want %q", deps, dep.ID)
	}
}
