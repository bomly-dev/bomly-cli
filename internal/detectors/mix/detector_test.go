package mix

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixture(t *testing.T) {
	projectDir := filepath.Join("testdata", "project")
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:    projectDir,
		PackageManager: sdk.PackageManagerMix,
		Ecosystem:      sdk.EcosystemElixir,
	})
	if err != nil {
		t.Fatalf("ResolveGraph returned error: %v", err)
	}
	graph := result.Graphs.Entries[0].Graph
	if graph == nil {
		t.Fatal("expected graph")
	}
	plug, ok := graph.Node("plug@1.15.3")
	if !ok {
		t.Fatalf("expected plug package, got %v", graph.Nodes())
	}
	if plug.PURL != "pkg:hex/plug@1.15.3" {
		t.Fatalf("expected plug PURL, got %q", plug.PURL)
	}
	credo, ok := graph.Node("credo@1.7.7")
	if !ok {
		t.Fatalf("expected credo package, got %v", graph.Nodes())
	}
	if string(credo.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected credo development scope, got %q", string(credo.PrimaryScope()))
	}
	deps, err := graph.DirectDependencies("root")
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected two direct dependencies, got %d", len(deps))
	}
}
