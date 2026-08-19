package swiftpm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

// A Package.resolved pin says how SwiftPM obtained a package. Source-control
// pins name a repository and the commit that was resolved; registry pins are
// identity-only; local pins point at a checkout on this machine.
func TestSwiftPMOriginByPinKind(t *testing.T) {
	resolved := []byte(`{
      "pins": [
        {
          "identity": "swift-argument-parser",
          "kind": "remoteSourceControl",
          "location": "https://github.com/apple/swift-argument-parser.git",
          "state": {"revision": "8192a3b4c5d6e7f8091a2b3c4d5e6f7081921324", "version": "1.3.0"}
        },
        {
          "identity": "internal-tools",
          "kind": "registry",
          "state": {"version": "2.0.0"}
        },
        {
          "identity": "local-helper",
          "kind": "localSourceControl",
          "location": "/Users/someone/src/local-helper",
          "state": {"revision": "92a3b4c5d6e7f8091a2b3c4d5e6f708192132435", "version": "0.1.0"}
        }
      ],
      "version": 2
    }`)

	graph, err := depGraphFromSwiftPM(resolved, nil)
	if err != nil {
		t.Fatalf("depGraphFromSwiftPM() error = %v", err)
	}

	var checked int
	for _, node := range graph.Nodes() {
		origin := detectors.OriginFrom(node.Metadata)
		switch node.Name {
		case "swift-argument-parser":
			checked++
			want := detectors.Origin{
				VCSURL:      "https://github.com/apple/swift-argument-parser.git",
				VCSRevision: "8192a3b4c5d6e7f8091a2b3c4d5e6f7081921324",
			}
			if origin != want {
				t.Errorf("%s origin = %+v, want %+v", node.Name, origin, want)
			}
		case "internal-tools", "local-helper":
			checked++
			if !origin.Empty() {
				t.Errorf("%s asserted an origin it should not have: %+v", node.Name, origin)
			}
		}
	}
	if checked != 3 {
		t.Fatalf("checked %d pins, want 3", checked)
	}
}

// `swift package show-dependencies` reports a repository and a version but no
// revision, so the native path alone would export unpinned repositories while
// the committed-file fallback exports pinned ones. The pins are read back from
// Package.resolved and joined onto the graph.
func TestSwiftPMNativeOriginIsPinnedFromPackageResolved(t *testing.T) {
	workingDir := t.TempDir()
	resolved := `{
      "pins": [
        {
          "identity": "swift-argument-parser",
          "kind": "remoteSourceControl",
          "location": "https://github.com/apple/swift-argument-parser.git",
          "state": {"revision": "f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b", "version": "1.3.0"}
        },
        {
          "identity": "local-helper",
          "kind": "localSourceControl",
          "location": "/Users/someone/src/local-helper",
          "state": {"revision": "091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c", "version": "0.1.0"}
        }
      ],
      "version": 2
    }`
	if err := os.WriteFile(filepath.Join(workingDir, "Package.resolved"), []byte(resolved), 0o644); err != nil {
		t.Fatal(err)
	}

	// `swift package show-dependencies` reports a URL and a version per node,
	// and no revision anywhere.
	showDependencies := []byte(`{
      "name": "demo",
      "url": "/workspace/demo",
      "version": "unspecified",
      "dependencies": [
        {"name": "swift-argument-parser", "url": "https://github.com/apple/swift-argument-parser.git", "version": "1.3.0", "dependencies": []},
        {"name": "local-helper", "url": "/Users/someone/src/local-helper", "version": "0.1.0", "dependencies": []}
      ]
    }`)

	g, err := nativeGraph(showDependencies, workingDir, zap.NewNop())
	if err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}

	want := detectors.Origin{
		VCSURL:      "https://github.com/apple/swift-argument-parser.git",
		VCSRevision: "f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b",
	}
	var checked int
	g.WalkNodes(func(dep *sdk.Dependency) bool {
		origin := detectors.OriginFrom(dep.Metadata)
		switch dep.Name {
		case "swift-argument-parser":
			checked++
			if origin != want {
				t.Errorf("remote origin = %+v, want %+v", origin, want)
			}
		case "local-helper":
			checked++
			// A local checkout is a path on this machine, pinned or not.
			if !origin.Empty() {
				t.Errorf("local package asserted an origin: %+v", origin)
			}
		}
		return true
	})
	if checked != 2 {
		t.Fatalf("checked %d packages, want 2", checked)
	}
}

// A project with no Package.resolved keeps whatever the native graph carried.
func TestSwiftPMNativeOriginSurvivesMissingPackageResolved(t *testing.T) {
	showDependencies := []byte(`{
      "name": "demo",
      "url": "/workspace/demo",
      "version": "unspecified",
      "dependencies": [
        {"name": "swift-argument-parser", "url": "https://github.com/apple/swift-argument-parser.git", "version": "1.3.0", "dependencies": []}
      ]
    }`)

	g, err := nativeGraph(showDependencies, t.TempDir(), zap.NewNop())
	if err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}

	want := detectors.Origin{VCSURL: "https://github.com/apple/swift-argument-parser.git"}
	var checked int
	g.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Name == "swift-argument-parser" {
			checked++
			if got := detectors.OriginFrom(dep.Metadata); got != want {
				t.Fatalf("origin = %+v, want the unpinned repository %+v", got, want)
			}
		}
		return true
	})
	if checked != 1 {
		t.Fatal("expected the remote package in the graph")
	}
}
