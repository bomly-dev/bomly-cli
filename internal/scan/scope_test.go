package scan

import (
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestFilterGraphByScope(t *testing.T) {
	depsGraph := model.New()
	root := model.NewPackage(model.Package{Name: "app", Version: "1.0.0"})
	runtimeDep := model.NewPackage(model.Package{Name: "react", Version: "18.2.0", Scope: string(ScopeRuntime)})
	devDep := model.NewPackage(model.Package{Name: "vitest", Version: "2.0.0", Scope: string(ScopeDevelopment)})
	for _, pkg := range []*model.Package{root, runtimeDep, devDep} {
		if err := depsGraph.AddPackage(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	if err := depsGraph.AddDependency(root.ID, runtimeDep.ID); err != nil {
		t.Fatalf("add runtime dependency: %v", err)
	}
	if err := depsGraph.AddDependency(root.ID, devDep.ID); err != nil {
		t.Fatalf("add development dependency: %v", err)
	}

	filtered, err := FilterGraphByScope(depsGraph, ScopeRuntime)
	if err != nil {
		t.Fatalf("FilterGraphByScope() error = %v", err)
	}
	if filtered.Size() != 2 {
		t.Fatalf("expected 2 packages after runtime filter, got %d", filtered.Size())
	}
	if _, ok := filtered.Package(runtimeDep.ID); !ok {
		t.Fatal("expected runtime dependency to be kept")
	}
	if _, ok := filtered.Package(devDep.ID); ok {
		t.Fatal("expected development dependency to be removed")
	}
}
