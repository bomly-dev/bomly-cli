package pub

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

// originOf returns the origin a node publishes, or the zero value when it has
// none, so cases can compare plain structs.
func originOf(dep *sdk.DependencyNode) sdk.DependencyOrigin {
	if dep == nil {
		return sdk.DependencyOrigin{}
	}
	if origin := dep.Origin.Normalized(); origin != nil {
		return *origin
	}
	return sdk.DependencyOrigin{}
}

// A pubspec.lock hosted package's description URL is the pub server, shared by
// every hosted package, and a path package is local. Only a git package names
// where its own code came from.
func TestPubOriginBySourceType(t *testing.T) {
	lock := []byte(`packages:
  collection:
    dependency: transitive
    description:
      name: collection
      sha256: abc
      url: "https://pub.dev"
    source: hosted
    version: "1.18.0"
  corp_widgets:
    dependency: transitive
    description:
      name: corp_widgets
      sha256: def
      url: "https://dart.corp/internal/feed"
    source: hosted
    version: "3.1.0"
  helper:
    dependency: "direct main"
    description:
      url: "https://github.com/example/helper.git"
      ref: main
      resolved-ref: a3b4c5d6e7f8091a2b3c4d5e6f70819213243546
      path: "."
    source: git
    version: "2.0.0"
  local_tools:
    dependency: "direct dev"
    description:
      path: "../local_tools"
      relative: true
    source: path
    version: "0.1.0"
`)
	manifest := pubspec{
		Name:            "demo",
		Version:         "1.0.0",
		Dependencies:    map[string]any{"helper": "any"},
		DevDependencies: map[string]any{"local_tools": "any"},
	}

	graph, err := depGraphFromLock(lock, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}

	cases := []struct {
		id   string
		want sdk.DependencyOrigin
	}{
		{id: "collection@1.18.0"},
		// A self-hosted pub server's URL has a path, so nothing but the
		// source kind distinguishes it from a repository URL.
		{id: "corp_widgets@3.1.0"},
		{id: "helper@2.0.0", want: sdk.DependencyOrigin{
			Repository: "https://github.com/example/helper.git",
			Revision:   "a3b4c5d6e7f8091a2b3c4d5e6f70819213243546",
		}},
		{id: "local_tools@0.1.0"},
	}
	for _, tc := range cases {
		node, ok := graph.Node(tc.id)
		if !ok {
			t.Fatalf("expected %s in graph", tc.id)
		}
		if got := originOf(node); got != tc.want {
			t.Errorf("%s origin = %+v, want %+v", tc.id, got, tc.want)
		}
	}
}

// `dart pub deps --json` reports a name, version, and kind but not a package's
// source description, so the native path alone would export no origin for git
// dependencies. The descriptions are read back from pubspec.lock.
func TestPubNativeOriginIsReadFromPubspecLock(t *testing.T) {
	workingDir := t.TempDir()
	lock := `packages:
  helper:
    dependency: "direct main"
    description:
      url: "https://github.com/example/helper.git"
      ref: main
      resolved-ref: 1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d
      path: "."
    source: git
    version: "2.0.0"
  collection:
    dependency: transitive
    description:
      name: collection
      sha256: abc
      url: "https://pub.dev"
    source: hosted
    version: "1.18.0"
  local_tools:
    dependency: "direct dev"
    description:
      path: "../local_tools"
      relative: true
    source: path
    version: "0.1.0"
`
	if err := os.WriteFile(filepath.Join(workingDir, "pubspec.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	// `dart pub deps --json` reports a name, version, kind, and source per
	// package, and no source description at all.
	depsJSON := []byte(`{
      "root": "demo",
      "packages": [
        {"name": "demo", "version": "1.0.0", "kind": "root", "source": "root", "dependencies": ["helper", "collection", "local_tools"]},
        {"name": "helper", "version": "2.0.0", "kind": "direct", "source": "git", "dependencies": []},
        {"name": "collection", "version": "1.18.0", "kind": "transitive", "source": "hosted", "dependencies": []},
        {"name": "local_tools", "version": "0.1.0", "kind": "dev", "source": "path", "dependencies": []}
      ]
    }`)

	g, err := nativeGraph(depsJSON, workingDir, zap.NewNop())
	if err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}

	want := sdk.DependencyOrigin{
		Repository: "https://github.com/example/helper.git",
		Revision:   "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d",
	}
	var checked int
	g.WalkNodes(func(dep sdk.GraphNode) bool {
		origin := originOf(dep)
		switch dep.Name {
		case "helper":
			checked++
			if origin != want {
				t.Errorf("helper origin = %+v, want %+v", origin, want)
			}
		case "collection", "local_tools":
			checked++
			if !origin.Empty() {
				t.Errorf("%s asserted an origin: %+v", dep.Name, origin)
			}
		}
		return true
	})
	if checked != 3 {
		t.Fatalf("checked %d packages, want 3", checked)
	}
}

// An override can point a package at a local path while pubspec.lock still
// describes the git dependency it replaced. The built code is local, so it must
// not be credited to that repository.
func TestPubOverriddenPackageIsNotCreditedToTheLockedRepository(t *testing.T) {
	workingDir := t.TempDir()
	lock := `packages:
  helper:
    dependency: "direct main"
    description:
      url: "https://github.com/example/helper.git"
      ref: main
      resolved-ref: 3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f
      path: "."
    source: git
    version: "2.0.0"
`
	if err := os.WriteFile(filepath.Join(workingDir, "pubspec.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	depsJSON := []byte(`{
      "root": "demo",
      "packages": [
        {"name": "demo", "version": "1.0.0", "kind": "root", "source": "root", "dependencies": ["helper"]},
        {"name": "helper", "version": "2.0.0", "kind": "direct", "source": "path", "dependencies": []}
      ]
    }`)

	g, err := nativeGraph(depsJSON, workingDir, zap.NewNop())
	if err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}

	var checked int
	g.WalkNodes(func(dep sdk.GraphNode) bool {
		if dep.Name != "helper" {
			return true
		}
		checked++
		if got := originOf(dep); !got.Empty() {
			t.Fatalf("overridden package origin = %+v, want none", got)
		}
		return true
	})
	if checked != 1 {
		t.Fatal("expected the overridden package in the graph")
	}
}

// A project with no pubspec.lock keeps the graph as it is.
func TestPubNativeOriginSurvivesMissingLock(t *testing.T) {
	depsJSON := []byte(`{
      "root": "demo",
      "packages": [
        {"name": "demo", "version": "1.0.0", "kind": "root", "source": "root", "dependencies": ["helper"]},
        {"name": "helper", "version": "2.0.0", "kind": "direct", "source": "git", "dependencies": []}
      ]
    }`)

	g, err := nativeGraph(depsJSON, t.TempDir(), zap.NewNop())
	if err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}

	var checked int
	g.WalkNodes(func(dep sdk.GraphNode) bool {
		if dep.Name == "helper" {
			checked++
		}
		if got := originOf(dep); !got.Empty() {
			t.Fatalf("%s origin = %+v, want none", dep.Name, got)
		}
		return true
	})
	if checked != 1 {
		t.Fatalf("found %d helper nodes, want 1", checked)
	}
}

// Loggers may be nil; a best-effort join must not be the thing that panics.
func TestPubNativeOriginToleratesNilLogger(t *testing.T) {
	workingDir := t.TempDir()
	depsJSON := []byte(`{"root":"demo","packages":[{"name":"demo","version":"1.0.0","kind":"root","source":"root","dependencies":[]}]}`)
	if err := os.WriteFile(filepath.Join(workingDir, "pubspec.lock"), []byte("packages:\n  helper:\n    source: git\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeGraph(depsJSON, workingDir, nil); err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}
	// An unparseable lock reaches the debug log, which is where a nil logger bites.
	if err := os.WriteFile(filepath.Join(workingDir, "pubspec.lock"), []byte("packages: [oops"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeGraph(depsJSON, workingDir, nil); err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}
}
