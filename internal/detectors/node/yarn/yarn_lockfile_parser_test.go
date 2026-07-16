package yarn

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestYarnLockfileParserRetainsUnreferencedEntries(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "left-pad": "^1.3.0"
  }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "yarn.lock"), []byte(`left-pad@^1.3.0:
  version "1.3.0"

bcrypt-pbkdf@^1.0.0:
  version "1.0.2"

tweetnacl@^0.14.0:
  version "0.14.5"
`), 0o644); err != nil {
		t.Fatalf("write yarn.lock: %v", err)
	}

	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	graph := result.Graphs.Entries[0].Graph
	if graph.Size() != 4 {
		t.Fatalf("expected root plus every lockfile package, got %d", graph.Size())
	}
	if dependency, ok := graph.Node("bcrypt-pbkdf@1.0.2"); !ok || dependency.Relationship != sdk.DependencyRelationshipUnknown {
		t.Fatalf("expected unreferenced bcrypt-pbkdf entry with unknown relationship, got %#v", dependency)
	}
	if dependency, ok := graph.Node("tweetnacl@0.14.5"); !ok || dependency.Relationship != sdk.DependencyRelationshipUnknown {
		t.Fatalf("expected unreferenced tweetnacl entry with unknown relationship, got %#v", dependency)
	}
	roots := graph.Roots()
	if len(roots) != 1 {
		t.Fatalf("expected single root package, got %d", len(roots))
	}
	if roots[0] == nil || roots[0].ID != "demo-app@1.0.0" {
		t.Fatalf("expected app root demo-app@1.0.0, got %#v", roots[0])
	}
}

func TestYarnBerryParsesQuotedNamesAliasesAndDependencies(t *testing.T) {
	projectDir := t.TempDir()
	manifest := []byte(`{"name":"demo","version":"1.0.0","dependencies":{"alias":"npm:real-package@^1.0.0"}}`)
	lockfile := []byte(`__metadata:
  version: 8

"alias@npm:real-package@^1.0.0":
  version: 1.2.3
  resolution: "real-package@npm:1.2.3"
  dependencies:
    "@esbuild/aix-ppc64": "npm:0.25.0"

"@esbuild/aix-ppc64@npm:0.25.0":
  version: 0.25.0
  resolution: "@esbuild/aix-ppc64@npm:0.25.0"
`)
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "yarn.lock"), lockfile, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatal(err)
	}
	graph := result.Graphs.Entries[0].Graph
	realPackage, ok := graph.Node("real-package@1.2.3")
	if !ok || realPackage.Source != sdk.DependencySourceRegistry {
		t.Fatalf("real package = %#v", realPackage)
	}
	esbuild, ok := graph.Node("@esbuild/aix-ppc64@0.25.0")
	if !ok {
		t.Fatalf("expected canonical scoped package name; nodes=%#v", graph.Nodes())
	}
	children, err := graph.DirectDependencies(realPackage.ID)
	if err != nil || len(children) != 1 || children[0].ID != esbuild.ID {
		t.Fatalf("dependencies = %#v, err=%v", children, err)
	}
}

func TestYarnLockfilePreservesMultipleVersions(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"demo","dependencies":{"parent":"1.0.0","lodash":"4.17.21"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "yarn.lock"), []byte(`parent@1.0.0:
  version "1.0.0"
  dependencies:
    lodash "3.10.1"

lodash@3.10.1:
  version "3.10.1"

lodash@4.17.21:
  version "4.17.21"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatal(err)
	}
	graph := result.Graphs.Entries[0].Graph
	for _, id := range []string{"lodash@3.10.1", "lodash@4.17.21"} {
		if _, ok := graph.Node(id); !ok {
			t.Fatalf("missing %s", id)
		}
	}
}
