package engine

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestFilterGraphByScope(t *testing.T) {
	depsGraph := sdk.New()
	root := sdk.NewDependency(sdk.Dependency{Name: "app", Version: "1.0.0"})
	runtimeDep := sdk.NewDependency(sdk.Dependency{Name: "react", Version: "18.2.0", Scopes: sdk.ScopesOf(ScopeRuntime)})
	devDep := sdk.NewDependency(sdk.Dependency{Name: "vitest", Version: "2.0.0", Scopes: sdk.ScopesOf(ScopeDevelopment)})
	for _, pkg := range []*sdk.Dependency{root, runtimeDep, devDep} {
		if err := depsGraph.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	if err := depsGraph.AddEdge(root.ID, runtimeDep.ID); err != nil {
		t.Fatalf("add runtime dependency: %v", err)
	}
	if err := depsGraph.AddEdge(root.ID, devDep.ID); err != nil {
		t.Fatalf("add development dependency: %v", err)
	}

	filtered, err := FilterGraphByScope(depsGraph, ScopeRuntime)
	if err != nil {
		t.Fatalf("FilterGraphByScope() error = %v", err)
	}
	if filtered.Size() != 2 {
		t.Fatalf("expected 2 packages after runtime filter, got %d", filtered.Size())
	}
	if _, ok := filtered.Node(runtimeDep.ID); !ok {
		t.Fatal("expected runtime dependency to be kept")
	}
	if _, ok := filtered.Node(devDep.ID); ok {
		t.Fatal("expected development dependency to be removed")
	}
}
