package swiftpm

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
		PackageManager: model.PackageManagerSwiftPM,
		Ecosystem:      model.EcosystemSwift,
	})
	if err != nil {
		t.Fatalf("ResolveGraph returned error: %v", err)
	}
	graph := result.Graphs.Entries[0].Graph
	if graph == nil {
		t.Fatal("expected graph")
	}
	pkg, ok := graph.Package("swift-argument-parser@1.3.0")
	if !ok {
		t.Fatalf("expected swift-argument-parser package, got %v", graph.Packages())
	}
	if pkg.PURL != "pkg:swift/swift-argument-parser@1.3.0" {
		t.Fatalf("expected SwiftPM PURL, got %q", pkg.PURL)
	}
	deps, err := graph.Dependencies("root")
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected one direct dependency, got %d", len(deps))
	}
}
