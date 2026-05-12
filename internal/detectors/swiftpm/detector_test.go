package swiftpm

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
		PackageManager: sdk.PackageManagerSwiftPM,
		Ecosystem:      sdk.EcosystemSwift,
	})
	if err != nil {
		t.Fatalf("ResolveGraph returned error: %v", err)
	}
	graph := result.Graphs.Entries[0].Graph
	if graph == nil {
		t.Fatal("expected graph")
	}
	pkg, ok := graph.Package("github.com/apple:swift-argument-parser@1.3.0")
	if !ok {
		t.Fatalf("expected swift-argument-parser package, got %v", graph.Packages())
	}
	if pkg.Org != "github.com/apple" {
		t.Fatalf("expected SwiftPM namespace, got %q", pkg.Org)
	}
	if pkg.PURL != "pkg:swift/github.com/apple/swift-argument-parser@1.3.0" {
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
