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
	pkg, ok := g.Node("test@1.25.8")
	if !ok {
		t.Fatal("expected test package")
	}
	if string(pkg.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scope, got %q", string(pkg.PrimaryScope()))
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
	root, ok := g.Node("demo@1.0.0")
	if !ok {
		t.Fatal("expected root package")
	}
	deps, err := g.DirectDependencies(root.ID)
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected three direct dependencies, got %d", len(deps))
	}
	dev, ok := g.Node("test@1.25.8")
	if !ok {
		t.Fatal("expected test package")
	}
	if string(dev.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected dev scope, got %q", string(dev.PrimaryScope()))
	}
	if dev.PURL != "pkg:pub/test@1.25.8" {
		t.Fatalf("unexpected purl %q", dev.PURL)
	}
}

func TestDepGraphFromPubDepsJSONBuildsTransitiveScopes(t *testing.T) {
	raw := []byte(`{
  "root": "demo",
  "packages": [
    {"name": "demo", "version": "1.0.0", "kind": "root", "source": "root", "dependencies": ["path", "test"]},
    {"name": "path", "version": "1.9.0", "kind": "direct", "source": "hosted", "dependencies": ["collection"]},
    {"name": "test", "version": "1.25.8", "kind": "dev", "source": "hosted", "dependencies": ["collection"]},
    {"name": "collection", "version": "1.18.0", "kind": "transitive", "source": "hosted", "dependencies": []}
  ]
}`)
	graph, err := depGraphFromPubDepsJSON(raw)
	if err != nil {
		t.Fatalf("depGraphFromPubDepsJSON() error = %v", err)
	}

	collection, ok := graph.Node("collection@1.18.0")
	if !ok {
		t.Fatalf("expected collection package, got %v", graph.Nodes())
	}
	if string(collection.PrimaryScope()) != string(sdk.ScopeRuntime) {
		t.Fatalf("expected shared transitive dependency to be runtime, got %q", string(collection.PrimaryScope()))
	}

	testPkg, ok := graph.Node("test@1.25.8")
	if !ok {
		t.Fatal("expected test package")
	}
	if string(testPkg.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected dev direct dependency, got %q", string(testPkg.PrimaryScope()))
	}
}
