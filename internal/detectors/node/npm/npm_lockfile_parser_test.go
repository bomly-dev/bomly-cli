package npm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestNPMLockfileAcceptsUTF8BOM(t *testing.T) {
	projectDir := t.TempDir()
	manifest := append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`)...)
	lockfile := append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}}`)...)
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), lockfile, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	graph, err := result.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := graph.Node("left-pad@1.3.0"); !ok {
		t.Fatal("expected BOM-prefixed files to resolve left-pad")
	}
}

func TestNPMShrinkwrapTakesPrecedence(t *testing.T) {
	projectDir := t.TempDir()
	packageLock := []byte(`{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"from-package-lock":"1.0.0"}},"node_modules/from-package-lock":{"version":"1.0.0"}}}`)
	shrinkwrap := []byte(`{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"from-shrinkwrap":"2.0.0"}},"node_modules/from-shrinkwrap":{"version":"2.0.0"}}}`)
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), packageLock, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "npm-shrinkwrap.json"), shrinkwrap, 0o644); err != nil {
		t.Fatal(err)
	}
	graphs, err := depGraphFromNPMLockfile(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	if graphs.lockfileName != "npm-shrinkwrap.json" {
		t.Fatalf("lockfile = %q", graphs.lockfileName)
	}
	if _, ok := graphs.graph.Node("from-shrinkwrap@2.0.0"); !ok {
		t.Fatal("expected shrinkwrap dependency")
	}
	if _, ok := graphs.graph.Node("from-package-lock@1.0.0"); ok {
		t.Fatal("package-lock must not be combined with shrinkwrap")
	}
}

func TestNPMLockfileRetainsUnknownComponent(t *testing.T) {
	projectDir := t.TempDir()
	lockfile := []byte(`{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/orphan":{"version":"1.0.0","dependencies":{"child":"2.0.0"}},"node_modules/child":{"version":"2.0.0"}}}`)
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), lockfile, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatal(err)
	}
	graph := result.Graphs.Entries[0].Graph
	orphan, ok := graph.Node("orphan@1.0.0")
	if !ok || orphan.Relationship != sdk.DependencyRelationshipUnknown {
		t.Fatalf("orphan = %#v", orphan)
	}
	child, ok := graph.Node("child@2.0.0")
	if !ok || child.Relationship != "" {
		t.Fatalf("child = %#v", child)
	}
}

func TestNPMLockfilePreservesMultipleInstalledVersions(t *testing.T) {
	projectDir := t.TempDir()
	lockfile := []byte(`{
  "name":"demo","lockfileVersion":3,
  "packages":{
    "":{"name":"demo","dependencies":{"lodash":"4.17.21","legacy":"1.0.0"}},
    "node_modules/lodash":{"version":"4.17.21"},
    "node_modules/legacy":{"version":"1.0.0","dependencies":{"lodash":"3.10.1"}},
    "node_modules/legacy/node_modules/lodash":{"version":"3.10.1"}
  }
}`)
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), lockfile, 0o644); err != nil {
		t.Fatal(err)
	}
	graphs, err := depGraphFromNPMLockfile(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"lodash@4.17.21", "lodash@3.10.1"} {
		if _, ok := graphs.graph.Node(id); !ok {
			t.Fatalf("missing %s", id)
		}
	}
	children, err := graphs.graph.DirectDependencies("legacy@1.0.0")
	if err != nil || len(children) != 1 || children[0].ID != "lodash@3.10.1" {
		t.Fatalf("legacy dependencies = %#v, err=%v", children, err)
	}
}

func TestNPMLockfileClassifiesLocalFileDependency(t *testing.T) {
	projectDir := t.TempDir()
	lockfile := []byte(`{
  "name":"demo","lockfileVersion":3,
  "packages":{
    "":{"name":"demo","dependencies":{"local-lib":"file:../local-lib"}},
    "node_modules/local-lib":{"name":"local-lib","version":"1.0.0","resolved":"file:../local-lib"}
  }
}`)
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), lockfile, 0o644); err != nil {
		t.Fatal(err)
	}
	graphs, err := depGraphFromNPMLockfile(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	dependency, ok := graphs.graph.Node("local-lib@1.0.0")
	if !ok || dependency.Source != sdk.DependencySourceFile || dependency.Type == sdk.PackageTypeApplication {
		t.Fatalf("local dependency = %#v", dependency)
	}
}

func TestNPMLockfileParserAllowsArrayEngines(t *testing.T) {
	projectDir := t.TempDir()
	lockfile := []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo-app",
      "version": "1.0.0",
      "dependencies": {
        "benchmark": "1.0.0"
      }
    },
    "node_modules/benchmark": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/benchmark/-/benchmark-1.0.0.tgz",
      "integrity": "sha512-example",
      "engines": [
        "node",
        "rhino"
      ]
    }
  }
}`)
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), lockfile, 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	graphs, err := depGraphFromNPMLockfile(projectDir)
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile() error = %v", err)
	}
	pkg, ok := graphs.graph.Node("benchmark@1.0.0")
	if !ok {
		t.Fatalf("expected benchmark@1.0.0 package")
	}
	if _, ok := pkg.Metadata[sdk.MetadataKeyNPM]; ok {
		t.Fatalf("expected array engines to be ignored, got metadata: %+v", pkg.Metadata)
	}
}

func TestResolveNPMLockDependencyIDFallsBackDeterministically(t *testing.T) {
	lockfile := npmPackageLock{
		Packages: map[string]npmLockPackage{
			"node_modules/z-parent/node_modules/shared": {
				Name:    "shared",
				Version: "1.2.3",
			},
			"node_modules/a-parent/node_modules/shared": {
				Name:    "shared",
				Version: "1.2.3",
			},
		},
	}
	pathToID := map[string]string{
		"node_modules/z-parent/node_modules/shared": "pkg:npm/shared@1.2.3-z",
		"node_modules/a-parent/node_modules/shared": "pkg:npm/shared@1.2.3-a",
	}

	got, ok := resolveNPMLockDependencyID("node_modules/example", "shared", "1.2.3", lockfile, pathToID)
	if !ok {
		t.Fatal("expected fallback dependency resolution to succeed")
	}
	if got != "pkg:npm/shared@1.2.3-a" {
		t.Fatalf("expected lexicographically first package path to win, got %q", got)
	}
}

func TestResolveNPMLockDependencyIDResolvesHoistedFromTopLevelParent(t *testing.T) {
	lockfile := npmPackageLock{
		Packages: map[string]npmLockPackage{
			"node_modules/cliui/node_modules/string-width": {
				Name:    "string-width",
				Version: "3.1.0",
			},
			"node_modules/string-width": {
				Name:    "string-width",
				Version: "2.1.1",
			},
		},
	}
	pathToID := map[string]string{
		"node_modules/cliui/node_modules/string-width": "pkg:npm/string-width@3.1.0",
		"node_modules/string-width":                    "pkg:npm/string-width@2.1.1",
	}

	got, ok := resolveNPMLockDependencyID("node_modules/wide-align", "string-width", "^1.0.2 || 2", lockfile, pathToID)
	if !ok {
		t.Fatal("expected hoisted dependency resolution to succeed")
	}
	if got != "pkg:npm/string-width@2.1.1" {
		t.Fatalf("expected top-level hoisted package to be selected, got %q", got)
	}
}
