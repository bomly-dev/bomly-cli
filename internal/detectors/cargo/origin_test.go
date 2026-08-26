package cargo

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

// originOf returns the origin a node publishes, or the zero value when it has
// none, so cases can compare plain structs.
func originOf(dep *sdk.Dependency) sdk.DependencyOrigin {
	if dep == nil {
		return sdk.DependencyOrigin{}
	}
	if origin := dep.Origin.Normalized(); origin != nil {
		return *origin
	}
	return sdk.DependencyOrigin{}
}

// Cargo.lock records one source string per package. Only "git+" names where the
// code came from; the index prefixes name a registry, and path or workspace
// members carry no source at all.
func TestSetCargoOriginBySourcePrefix(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   sdk.DependencyOrigin
	}{
		{
			name:   "git dependency pins the resolved commit in the fragment",
			source: "git+https://github.com/example/helper?rev=main#3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f",
			want:   sdk.DependencyOrigin{Repository: "https://github.com/example/helper", Revision: "3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f"},
		},
		{
			name:   "requested tag is used when no commit was recorded",
			source: "git+https://github.com/example/helper?tag=v1.2.3",
			want:   sdk.DependencyOrigin{Repository: "https://github.com/example/helper", Revision: "v1.2.3"},
		},
		{
			name:   "branch dependency without a pin keeps the repository",
			source: "git+https://github.com/example/helper",
			want:   sdk.DependencyOrigin{Repository: "https://github.com/example/helper"},
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
			if got := originOf(node); got != tc.want {
				t.Fatalf("origin = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Cargo can resolve one crate name and version from two sources -- the same
// crate pulled from two git remotes. Cargo's package IDs are source-qualified,
// so these are distinguishable occurrences: both stay in the graph, each with
// its own origin, rather than one being folded into the other.
func TestCargoDuplicateCrateSourcesStayDistinct(t *testing.T) {
	metadata := []byte(`{
      "packages": [
        {"id": "demo 0.1.0 (path+file:///w)", "name": "demo", "version": "0.1.0", "source": null, "dependencies": []},
        {"id": "helper 1.0.0 (git+https://github.com/a/helper#aaaa)", "name": "helper", "version": "1.0.0", "source": "git+https://github.com/a/helper#aaaabbbbccccddddeeeeffff0000111122223333", "dependencies": []},
        {"id": "helper 1.0.0 (git+https://github.com/b/helper#bbbb)", "name": "helper", "version": "1.0.0", "source": "git+https://github.com/b/helper#bbbbccccddddeeeeffff00001111222233334444", "dependencies": []}
      ],
      "workspace_members": ["demo 0.1.0 (path+file:///w)"],
      "resolve": {"nodes": [], "root": "demo 0.1.0 (path+file:///w)"}
    }`)

	// Repeated: the packages arrive in a map, so an order-dependent result
	// would show up as instability rather than a stable answer.
	for range 25 {
		graph, err := depGraphFromMetadata(metadata)
		if err != nil {
			t.Fatalf("depGraphFromMetadata() error = %v", err)
		}
		repositories := map[string]int{}
		graph.WalkNodes(func(dep *sdk.Dependency) bool {
			if dep.Name != "helper" {
				return true
			}
			if origin := originOf(dep); origin.Repository != "" {
				repositories[origin.Repository]++
			}
			return true
		})
		if len(repositories) != 2 || repositories["https://github.com/a/helper"] != 1 || repositories["https://github.com/b/helper"] != 1 {
			t.Fatalf("helper occurrences = %v, want both repositories as distinct nodes", repositories)
		}
	}
}

// A crate can be resolved from the registry and from a git remote at one
// name@version (renamed dependencies). Only the git occurrence has a
// publishable origin, but they are still two resolutions: the registry
// occurrence must not vanish into the git node and take its repository.
func TestCargoRegistryAndGitOccurrencesStayDistinct(t *testing.T) {
	metadata := []byte(`{
      "packages": [
        {"id": "demo 0.1.0 (path+file:///w)", "name": "demo", "version": "0.1.0", "source": null, "dependencies": []},
        {"id": "helper 1.0.0 (git+https://github.com/a/helper#aaaa)", "name": "helper", "version": "1.0.0", "source": "git+https://github.com/a/helper#aaaabbbbccccddddeeeeffff0000111122223333", "dependencies": []},
        {"id": "helper 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)", "name": "helper", "version": "1.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index", "dependencies": []}
      ],
      "workspace_members": ["demo 0.1.0 (path+file:///w)"],
      "resolve": {"nodes": [], "root": "demo 0.1.0 (path+file:///w)"}
    }`)

	graph, err := depGraphFromMetadata(metadata)
	if err != nil {
		t.Fatalf("depGraphFromMetadata() error = %v", err)
	}

	var nodes, withOrigin, without int
	graph.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Name != "helper" {
			return true
		}
		nodes++
		if origin := originOf(dep); origin.Repository != "" {
			withOrigin++
			if dep.Source != sdk.DependencySourceGit {
				t.Fatalf("the %s occurrence claims the git repository", dep.Source)
			}
		} else {
			without++
			if dep.Source != sdk.DependencySourceRegistry {
				t.Fatalf("expected the origin-free occurrence to be the registry one, got %s", dep.Source)
			}
		}
		return true
	})
	if nodes != 2 || withOrigin != 1 || without != 1 {
		t.Fatalf("helper nodes = %d (with origin %d, without %d), want both occurrences distinct", nodes, withOrigin, without)
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
	want := sdk.DependencyOrigin{
		Repository: "https://github.com/a/helper",
		Revision:   "aaaabbbbccccddddeeeeffff0000111122223333",
	}
	var checked int
	graph.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Name == "helper" {
			checked++
			if got := originOf(dep); got != want {
				t.Fatalf("origin = %+v, want %+v", got, want)
			}
		}
		return true
	})
	if checked != 1 {
		t.Fatalf("found %d helper nodes, want 1", checked)
	}
}

// A workspace member is the project's own code. A lock entry that merely shares
// its name -- an unrelated crate pulled from a git remote -- must not be
// credited to it, or the SBOM reports first-party code as coming from someone
// else's repository.
//
// This covers origin only; the identity half of the collision (the member's
// version, its ResolvedURL, and the external crate's own node) is covered by
// the tests in identity_test.go.
func TestCargoWorkspaceMemberTakesNoExternalOrigin(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "helper"
version = "0.1.0"

[[package]]
name = "helper"
version = "1.0.0"
source = "git+https://github.com/external/helper#aaaabbbbccccddddeeeeffff0000111122223333"
`)
	root := cargoManifest{Name: "demo", Version: "0.1.0"}
	members := []cargoLockMember{{manifest: cargoManifest{Name: "helper", Version: "0.1.0"}, dir: "crates/helper"}}

	graph, _, _, err := depGraphFromLockWorkspace(lock, root, members, sdk.Scope(""))
	if err != nil {
		t.Fatalf("depGraphFromLockWorkspace() error = %v", err)
	}

	var checked int
	graph.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Type != sdk.PackageTypeApplication {
			return true
		}
		checked++
		if origin := originOf(dep); !origin.Empty() {
			t.Fatalf("%s is the project's own code but claims %+v", dep.ID, origin)
		}
		return true
	})
	if checked == 0 {
		t.Fatal("expected at least one workspace member in the graph")
	}
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
	want := sdk.DependencyOrigin{Repository: "https://github.com/example/helper", Revision: "6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192"}
	if got := originOf(helper); got != want {
		t.Fatalf("helper origin = %+v, want %+v", got, want)
	}
	serde, ok := graph.Node("serde@1.0.0")
	if !ok {
		t.Fatal("expected serde in graph")
	}
	if got := originOf(serde); !got.Empty() {
		t.Fatalf("registry crate asserted an origin: %+v", got)
	}
}

// The Cargo.lock fallback carries the same source-qualified records as cargo
// metadata, referenced by qualified dependency strings when a bare name would
// be ambiguous. Both occurrences stay distinct there too, and no node ID
// embeds the raw source URL -- IDs become SBOM component identifiers, and a
// source can carry credentials.
func TestCargoLockDuplicateSourcesStayDistinctWithOpaqueIDs(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = [
 "helper 1.0.0 (git+https://token:s3cret@git.corp/a/helper)",
]

[[package]]
name = "helper"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "helper"
version = "1.0.0"
source = "git+https://token:s3cret@git.corp/a/helper#aaaabbbbccccddddeeeeffff0000111122223333"
`)
	manifest := []byte("[package]\nname = \"demo\"\nversion = \"0.1.0\"\n")

	graph, err := depGraphFromLockWithScope(lock, manifest, sdk.Scope(""))
	if err != nil {
		t.Fatalf("depGraphFromLockWithScope() error = %v", err)
	}

	var nodes int
	graph.WalkNodes(func(dep *sdk.Dependency) bool {
		if strings.Contains(dep.ID, "s3cret") || strings.Contains(dep.ID, "git.corp") {
			t.Fatalf("node ID %q embeds the raw source", dep.ID)
		}
		if dep.Name == "helper" {
			nodes++
		}
		return true
	})
	if nodes != 2 {
		t.Fatalf("helper nodes = %d, want both source-qualified records", nodes)
	}
}
