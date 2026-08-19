package swiftpm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

// originOf returns the origin a node publishes, or the zero value when it has
// none, so cases can compare plain structs.
func originOf(dep *sdk.Dependency) sdk.PackageOrigin {
	if dep == nil {
		return sdk.PackageOrigin{}
	}
	if origin := dep.Origin.Normalized(); origin != nil {
		return *origin
	}
	return sdk.PackageOrigin{}
}

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
		origin := originOf(node)
		switch node.Name {
		case "swift-argument-parser":
			checked++
			want := sdk.PackageOrigin{
				Repository: "https://github.com/apple/swift-argument-parser.git",
				Revision:   "8192a3b4c5d6e7f8091a2b3c4d5e6f7081921324",
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

	want := sdk.PackageOrigin{
		Repository: "https://github.com/apple/swift-argument-parser.git",
		Revision:   "f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b",
	}
	var checked int
	g.WalkNodes(func(dep *sdk.Dependency) bool {
		origin := originOf(dep)
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

// `swift package edit <name> --path ...` points a dependency at a local
// checkout, and Package.resolved keeps the pin that checkout replaced. The
// package being built is the local code, so it must not be credited to the
// remote repository and commit that pin still names.
func TestSwiftPMEditedPackageIsNotCreditedToItsFormerPin(t *testing.T) {
	workingDir := t.TempDir()
	resolved := `{
      "pins": [
        {
          "identity": "helper",
          "kind": "remoteSourceControl",
          "location": "https://github.com/example/helper.git",
          "state": {"revision": "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e", "version": "1.0.0"}
        }
      ],
      "version": 2
    }`
	if err := os.WriteFile(filepath.Join(workingDir, "Package.resolved"), []byte(resolved), 0o644); err != nil {
		t.Fatal(err)
	}
	showDependencies := []byte(`{
      "name": "demo",
      "url": "/workspace/demo",
      "version": "unspecified",
      "dependencies": [
        {"name": "helper", "url": "/workspace/helper", "version": "unspecified", "dependencies": []}
      ]
    }`)

	g, err := nativeGraph(showDependencies, workingDir, zap.NewNop())
	if err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}

	var checked int
	g.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Name != "helper" {
			return true
		}
		checked++
		if got := originOf(dep); !got.Empty() {
			t.Fatalf("edited package origin = %+v, want none: it is built from a local checkout", got)
		}
		return true
	})
	if checked != 1 {
		t.Fatal("expected the edited package in the graph")
	}
}

// A package can be built from a mirror while Package.resolved still pins the
// upstream host. The names match, so an identity fallback would credit the
// build to a repository it never fetched from.
func TestSwiftPMPinIsNotAttachedToADifferentRepository(t *testing.T) {
	workingDir := t.TempDir()
	resolved := `{
      "pins": [
        {
          "identity": "helper",
          "kind": "remoteSourceControl",
          "location": "https://git.corp/team/helper.git",
          "state": {"revision": "aaaabbbbccccddddeeeeffff0000111122223333", "version": "1.0.0"}
        }
      ],
      "version": 2
    }`
	if err := os.WriteFile(filepath.Join(workingDir, "Package.resolved"), []byte(resolved), 0o644); err != nil {
		t.Fatal(err)
	}
	showDependencies := []byte(`{
      "name": "demo",
      "url": "/workspace/demo",
      "version": "unspecified",
      "dependencies": [
        {"name": "helper", "url": "https://mirror.corp/team/helper.git", "version": "2.0.0", "dependencies": []}
      ]
    }`)

	g, err := nativeGraph(showDependencies, workingDir, zap.NewNop())
	if err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}

	var checked int
	g.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.ResolvedURL == "" {
			return true
		}
		checked++
		origin := originOf(dep)
		if origin.Repository == "https://git.corp/team/helper.git" {
			t.Fatalf("a package built from a mirror was credited to %q", origin.Repository)
		}
		if origin.Revision != "" {
			t.Fatalf("origin = %+v, want no pin: the pinned repository is not this one", origin)
		}
		return true
	})
	if checked != 1 {
		t.Fatalf("checked %d packages, want 1", checked)
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

	want := sdk.PackageOrigin{Repository: "https://github.com/apple/swift-argument-parser.git"}
	var checked int
	g.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Name == "swift-argument-parser" {
			checked++
			if got := originOf(dep); got != want {
				t.Fatalf("origin = %+v, want the unpinned repository %+v", got, want)
			}
		}
		return true
	})
	if checked != 1 {
		t.Fatal("expected the remote package in the graph")
	}
}

// Loggers may be nil; a best-effort join must not be the thing that panics.
func TestSwiftPMNativeOriginToleratesNilLogger(t *testing.T) {
	workingDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workingDir, "Package.resolved"), []byte(`{"pins":[],"version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeGraph([]byte(`{"name":"demo","url":"/w","version":"unspecified","dependencies":[]}`), workingDir, nil); err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}
	// An unparseable file reaches the debug log, which is where a nil logger bites.
	if err := os.WriteFile(filepath.Join(workingDir, "Package.resolved"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeGraph([]byte(`{"name":"demo","url":"/w","version":"unspecified","dependencies":[]}`), workingDir, nil); err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}
}

// Repository paths are case-sensitive on a self-hosted host, so two packages
// differing only in path case are different repositories. Folding their keys
// together would attach one repository's pin to the other's package.
func TestSwiftPMRepositoryKeyPreservesPathCase(t *testing.T) {
	if repositoryKey("https://git.corp/Team/Helper.git") == repositoryKey("https://git.corp/team/helper.git") {
		t.Fatal("two repositories differing only in path case share a lookup key")
	}
	// Scheme and host are case-insensitive, so those spellings are one key.
	if repositoryKey("HTTPS://Git.Corp/Team/Helper.git") != repositoryKey("https://git.corp/Team/Helper.git") {
		t.Fatal("host casing should not change the key")
	}
	// The suffix and trailing slash still normalize away.
	if repositoryKey("https://git.corp/Team/Helper/") != repositoryKey("https://git.corp/Team/Helper.git") {
		t.Fatal("a trailing slash or .git suffix should not change the key")
	}
}

// A pin for a differently-cased path must not be attached to this package.
func TestSwiftPMNativeOriginDoesNotMatchAcrossPathCase(t *testing.T) {
	workingDir := t.TempDir()
	resolved := `{
      "pins": [
        {
          "identity": "other-helper",
          "kind": "remoteSourceControl",
          "location": "https://git.corp/team/helper.git",
          "state": {"revision": "5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081", "version": "1.0.0"}
        }
      ],
      "version": 2
    }`
	if err := os.WriteFile(filepath.Join(workingDir, "Package.resolved"), []byte(resolved), 0o644); err != nil {
		t.Fatal(err)
	}
	showDependencies := []byte(`{
      "name": "demo",
      "url": "/workspace/demo",
      "version": "unspecified",
      "dependencies": [
        {"name": "Helper", "url": "https://git.corp/Team/Helper.git", "version": "2.0.0", "dependencies": []}
      ]
    }`)

	g, err := nativeGraph(showDependencies, workingDir, zap.NewNop())
	if err != nil {
		t.Fatalf("nativeGraph() error = %v", err)
	}
	g.WalkNodes(func(dep *sdk.Dependency) bool {
		if origin := originOf(dep); origin.Revision == "5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081" {
			t.Fatalf("%s took a pin belonging to a differently-cased repository: %+v", dep.Name, origin)
		}
		return true
	})
}
