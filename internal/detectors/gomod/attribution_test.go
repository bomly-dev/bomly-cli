package gomod

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

// TestGoModLocationsCarryTheirModuleRoot covers the one place under
// internal/detectors that builds a PackageLocation by hand: the go.mod require
// line a direct dependency is declared on. The site belongs to the main
// module, and after ResolveGraph's tail it says so.
func TestGoModLocationsCarryTheirModuleRoot(t *testing.T) {
	raw := []byte(`
{"ImportPath":"example.com/demo","Module":{"Path":"example.com/demo","Main":true},"Imports":["github.com/direct/dep"]}
{"ImportPath":"github.com/direct/dep","Module":{"Path":"github.com/direct/dep","Version":"v1.0.0"},"Imports":["example.com/trans/dep"]}
{"ImportPath":"example.com/trans/dep","Module":{"Path":"example.com/trans/dep","Version":"v2.0.0"}}
`)
	g, err := depGraphFromGoList(raw, "example.com/demo", []moduleRef{{Path: "github.com/direct/dep", Version: "v1.0.0", Line: 7}})
	if err != nil {
		t.Fatalf("depGraphFromGoList: %v", err)
	}

	detectors.Attributed(sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"}),
	})

	direct, ok := testnodes.FindDep(g, "github.com/direct/dep@v1.0.0")
	if !ok {
		t.Fatal("direct dep missing from graph")
	}
	if len(direct.Locations) != 1 {
		t.Fatalf("expected the single go.mod site, got %+v", direct.Locations)
	}
	location := direct.Locations[0]
	if location.ModuleRoot != "." {
		t.Fatalf("module root = %q, want \".\": the main module declares this require line", location.ModuleRoot)
	}
	if location.Relationship != sdk.DependencyRelationshipDirect {
		t.Fatalf("relationship = %q, want direct: go.mod is where the main module declares it", location.Relationship)
	}
	if len(location.Scopes) != 1 || location.Scopes[0] != sdk.ScopeRuntime {
		t.Fatalf("site scopes = %v, want [runtime]", location.Scopes)
	}
}
