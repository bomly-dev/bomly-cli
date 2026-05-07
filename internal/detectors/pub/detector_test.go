package pub

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixtureProject(t *testing.T) {
	detector := Detector{WorkingDir: "testdata/project"}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     "testdata/project",
		PackageManager:  sdk.PackageManagerPub,
		Ecosystem:       sdk.EcosystemDart,
		ExecutionTarget: sdk.ExecutionTarget{Location: "testdata/project"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	pkg, ok := g.Package("test@1.25.8")
	if !ok {
		t.Fatal("expected test package")
	}
	if pkg.Scope != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scope, got %q", pkg.Scope)
	}
}

func TestDepGraphFromLockScopesDirectDependencies(t *testing.T) {
	lock := []byte(`packages:
  collection:
    dependency: transitive
    description:
      name: collection
      sha256: abc
      url: "https://pub.dev"
    source: hosted
    version: "1.18.0"
  path:
    dependency: "direct main"
    description:
      name: path
      url: "https://pub.dev"
    source: hosted
    version: "1.9.0"
  test:
    dependency: "direct dev"
    description:
      name: test
      url: "https://pub.dev"
    source: hosted
    version: "1.25.8"
`)
	manifest := pubspec{
		Name:            "demo",
		Version:         "1.0.0",
		Dependencies:    map[string]any{"path": "^1.9.0"},
		DevDependencies: map[string]any{"test": "^1.25.8"},
	}
	g, err := depGraphFromLock(lock, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	root, ok := g.Package("demo@1.0.0")
	if !ok {
		t.Fatal("expected root package")
	}
	deps, err := g.Dependencies(root.ID)
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected two direct dependencies, got %d", len(deps))
	}
	dev, ok := g.Package("test@1.25.8")
	if !ok {
		t.Fatal("expected test package")
	}
	if dev.Scope != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected dev scope, got %q", dev.Scope)
	}
	if dev.PURL != "pkg:pub/test@1.25.8" {
		t.Fatalf("unexpected purl %q", dev.PURL)
	}
}
