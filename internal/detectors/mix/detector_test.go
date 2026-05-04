package mix

import (
	"context"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixture(t *testing.T) {
	projectDir := filepath.Join("testdata", "project")
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), model.DetectionRequest{
		ProjectPath:    projectDir,
		PackageManager: model.PackageManagerMix,
		Ecosystem:      model.EcosystemElixir,
	})
	if err != nil {
		t.Fatalf("ResolveGraph returned error: %v", err)
	}
	graph := result.Graphs.Entries[0].Graph
	if graph == nil {
		t.Fatal("expected graph")
	}
	plug, ok := graph.Package("plug@1.15.3")
	if !ok {
		t.Fatalf("expected plug package, got %v", graph.Packages())
	}
	if plug.PURL != "pkg:hex/plug@1.15.3" {
		t.Fatalf("expected plug PURL, got %q", plug.PURL)
	}
	credo, ok := graph.Package("credo@1.7.7")
	if !ok {
		t.Fatalf("expected credo package, got %v", graph.Packages())
	}
	if credo.Scope != string(model.ScopeDevelopment) {
		t.Fatalf("expected credo development scope, got %q", credo.Scope)
	}
	deps, err := graph.Dependencies("root")
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected two direct dependencies, got %d", len(deps))
	}
}
