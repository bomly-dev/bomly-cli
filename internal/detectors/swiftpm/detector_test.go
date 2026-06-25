package swiftpm

import (
	"context"
	"os"
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
	pkg, ok := graph.Node("github.com/apple:swift-argument-parser@1.3.0")
	if !ok {
		t.Fatalf("expected swift-argument-parser package, got %v", graph.Nodes())
	}
	if pkg.Org != "github.com/apple" {
		t.Fatalf("expected SwiftPM namespace, got %q", pkg.Org)
	}
	if pkg.PURL != "pkg:swift/github.com/apple/swift-argument-parser@1.3.0" {
		t.Fatalf("expected SwiftPM PURL, got %q", pkg.PURL)
	}
	deps, err := graph.DirectDependencies("root")
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected one direct dependency, got %d", len(deps))
	}
}

func TestDepGraphFromSwiftShowDepsBuildsTransitiveGraph(t *testing.T) {
	raw := []byte(`{
  "name": "Demo",
  "dependencies": [
    {
      "name": "swift-argument-parser",
      "url": "https://github.com/apple/swift-argument-parser.git",
      "version": "1.3.0",
      "dependencies": [
        {
          "name": "swift-system",
          "url": "https://github.com/apple/swift-system.git",
          "version": "1.2.0",
          "dependencies": []
        }
      ]
    }
  ]
}`)
	graph, err := depGraphFromSwiftShowDeps(raw)
	if err != nil {
		t.Fatalf("depGraphFromSwiftShowDeps() error = %v", err)
	}

	parentID := "github.com/apple:swift-argument-parser@1.3.0"
	parent, ok := graph.Node(parentID)
	if !ok {
		t.Fatalf("expected swift-argument-parser package, got %v", graph.Nodes())
	}
	children, err := graph.DirectDependencies(parent.ID)
	if err != nil {
		t.Fatalf("swift-argument-parser dependencies: %v", err)
	}
	if len(children) != 1 || children[0].ID != "github.com/apple:swift-system@1.2.0" {
		t.Fatalf("expected swift-system transitive dependency, got %#v", children)
	}
}

func TestPackageResolvedPositionsPreferVersionAndFlushFallbacks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Package.resolved")
	raw := []byte(`{
  "pins": [
    {
      "identity": "swift-argument-parser",
      "state": {
        "revision": "abc",
        "version": "1.3.0"
      }
    },
    {
      "identity": "swift-system",
      "state": {
        "revision": "def"
      }
    },
    {
      "identity": "swift-log"
    }
  ]
}
`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write Package.resolved: %v", err)
	}

	positions := packageResolvedPositions(path, "Package.resolved")
	if got := positions["swift-argument-parser"]; got == nil || got.Line != 7 {
		t.Fatalf("swift-argument-parser position = %#v, want version line 7", got)
	}
	if got := positions["swift-system"]; got == nil || got.Line != 13 {
		t.Fatalf("swift-system position = %#v, want revision line 13", got)
	}
	if got := positions["swift-log"]; got == nil || got.Line != 17 {
		t.Fatalf("swift-log position = %#v, want identity fallback line 17", got)
	}
}
