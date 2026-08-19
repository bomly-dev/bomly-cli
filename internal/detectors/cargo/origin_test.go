package cargo

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

// Cargo.lock records one source string per package. Only "git+" names where the
// code came from; the index prefixes name a registry, and path or workspace
// members carry no source at all.
func TestSetCargoOriginBySourcePrefix(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   detectors.Origin
	}{
		{
			name:   "git dependency pins the resolved commit in the fragment",
			source: "git+https://github.com/example/helper?rev=main#3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f",
			want:   detectors.Origin{VCSURL: "https://github.com/example/helper", VCSRevision: "3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f"},
		},
		{
			name:   "requested tag is used when no commit was recorded",
			source: "git+https://github.com/example/helper?tag=v1.2.3",
			want:   detectors.Origin{VCSURL: "https://github.com/example/helper", VCSRevision: "v1.2.3"},
		},
		{
			name:   "branch dependency without a pin keeps the repository",
			source: "git+https://github.com/example/helper",
			want:   detectors.Origin{VCSURL: "https://github.com/example/helper"},
		},
		{name: "crates.io index root", source: "registry+https://github.com/rust-lang/crates.io-index"},
		{name: "sparse index root", source: "sparse+https://index.crates.io/"},
		{name: "path or workspace member", source: ""},
		{name: "credentialed private git remote", source: "git+https://token:s3cret-value-here@git.corp/team/helper#4d5e6f70"},
		{name: "ssh git remote", source: "git+ssh://git@github.com/example/helper#5e6f7081"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "helper", Version: "1.0.0"}})
			setCargoOrigin(node, tc.source)
			if got := detectors.OriginFrom(node.Metadata); got != tc.want {
				t.Fatalf("origin = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Cargo can resolve one crate name and version from two sources -- the same
// crate pulled from two git remotes. They share a PURL, so they become one
// node, and that node must not claim whichever source was walked first.
func TestCargoDuplicateCrateSourcesCancelOrigin(t *testing.T) {
	metadata := []byte(`{
      "packages": [
        {"id": "demo 0.1.0 (path+file:///w)", "name": "demo", "version": "0.1.0", "source": null, "dependencies": []},
        {"id": "helper 1.0.0 (git+https://github.com/a/helper#aaaa)", "name": "helper", "version": "1.0.0", "source": "git+https://github.com/a/helper#aaaabbbbccccddddeeeeffff0000111122223333", "dependencies": []},
        {"id": "helper 1.0.0 (git+https://github.com/b/helper#bbbb)", "name": "helper", "version": "1.0.0", "source": "git+https://github.com/b/helper#bbbbccccddddeeeeffff00001111222233334444", "dependencies": []}
      ],
      "workspace_members": ["demo 0.1.0 (path+file:///w)"],
      "resolve": {"nodes": [], "root": "demo 0.1.0 (path+file:///w)"}
    }`)

	// Repeat: the packages arrive in a map, so an order-dependent answer shows
	// up as a different result between runs rather than a stable wrong one.
	for range 25 {
		graph, err := depGraphFromMetadata(metadata)
		if err != nil {
			t.Fatalf("depGraphFromMetadata() error = %v", err)
		}
		var checked int
		graph.WalkNodes(func(dep *sdk.Dependency) bool {
			if dep.Name != "helper" {
				return true
			}
			checked++
			if got := detectors.OriginFrom(dep.Metadata); !got.Empty() {
				t.Fatalf("origin = %+v, want none: the crate resolved from two repositories", got)
			}
			return true
		})
		if checked != 1 {
			t.Fatalf("found %d helper nodes, want 1", checked)
		}
	}
}

// Two records naming the same source still publish it.
func TestCargoDuplicateCrateSameSourceKeepsOrigin(t *testing.T) {
	metadata := []byte(`{
      "packages": [
        {"id": "demo 0.1.0 (path+file:///w)", "name": "demo", "version": "0.1.0", "source": null, "dependencies": []},
        {"id": "helper 1.0.0 (git+https://github.com/a/helper#aaaa)", "name": "helper", "version": "1.0.0", "source": "git+https://github.com/a/helper#aaaabbbbccccddddeeeeffff0000111122223333", "dependencies": []},
        {"id": "helper 1.0.0 (git+https://github.com/a/helper#aaaa2)", "name": "helper", "version": "1.0.0", "source": "git+https://github.com/a/helper#aaaabbbbccccddddeeeeffff0000111122223333", "dependencies": []}
      ],
      "workspace_members": ["demo 0.1.0 (path+file:///w)"],
      "resolve": {"nodes": [], "root": "demo 0.1.0 (path+file:///w)"}
    }`)

	graph, err := depGraphFromMetadata(metadata)
	if err != nil {
		t.Fatalf("depGraphFromMetadata() error = %v", err)
	}
	want := detectors.Origin{
		VCSURL:      "https://github.com/a/helper",
		VCSRevision: "aaaabbbbccccddddeeeeffff0000111122223333",
	}
	graph.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Name == "helper" {
			if got := detectors.OriginFrom(dep.Metadata); got != want {
				t.Fatalf("origin = %+v, want %+v", got, want)
			}
		}
		return true
	})
}

// The lockfile path builds nodes through the same helper.
func TestCargoLockGraphCarriesOrigin(t *testing.T) {
	lock := []byte(`
[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["helper", "serde"]

[[package]]
name = "helper"
version = "1.0.0"
source = "git+https://github.com/example/helper?rev=main#6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
	manifest := []byte("[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\nhelper = { git = \"https://github.com/example/helper\" }\nserde = \"1\"\n")

	graph, err := depGraphFromLock(lock, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}

	helper, ok := graph.Node("helper@1.0.0")
	if !ok {
		t.Fatal("expected helper in graph")
	}
	want := detectors.Origin{VCSURL: "https://github.com/example/helper", VCSRevision: "6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192"}
	if got := detectors.OriginFrom(helper.Metadata); got != want {
		t.Fatalf("helper origin = %+v, want %+v", got, want)
	}
	serde, ok := graph.Node("serde@1.0.0")
	if !ok {
		t.Fatal("expected serde in graph")
	}
	if got := detectors.OriginFrom(serde.Metadata); !got.Empty() {
		t.Fatalf("registry crate asserted an origin: %+v", got)
	}
}
