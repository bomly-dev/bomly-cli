package npm

import (
	"github.com/bomly-dev/bomly-sdk"
	"os"
	"path/filepath"
	"testing"
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

// npm writes whatever it installed from into "resolved": a registry tarball,
// but also a git remote or a local path. Only the first is a location an SBOM
// can publish.
func TestNPMOriginByResolvedShape(t *testing.T) {
	projectDir := t.TempDir()
	lockfile := `{
      "name": "demo",
      "version": "1.0.0",
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "demo", "version": "1.0.0", "dependencies": {"from-registry": "1.0.0", "from-git": "1.0.0", "from-file": "1.0.0", "from-private": "1.0.0"}},
        "node_modules/from-registry": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/from-registry/-/from-registry-1.0.0.tgz"},
        "node_modules/from-git": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/owner/repo.git#9f8e7d6c5b4a3928176554433221100ffeeddcc0"},
        "node_modules/from-file": {"version": "1.0.0", "resolved": "file:../vendor/from-file"},
        "node_modules/from-private": {"version": "1.0.0", "resolved": "https://build:s3cret-token-value@nexus.corp/repo/from-private-1.0.0.tgz"}
      }
    }`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatal(err)
	}

	graphs, err := depGraphFromNPMLockfile(projectDir)
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile() error = %v", err)
	}

	cases := []struct {
		id   string
		want string
	}{
		{id: "from-registry@1.0.0", want: "https://registry.npmjs.org/from-registry/-/from-registry-1.0.0.tgz"},
		{id: "from-git@1.0.0"},     // a git remote npm can reach, not a published location
		{id: "from-file@1.0.0"},    // a path on the machine that ran npm install
		{id: "from-private@1.0.0"}, // carries a credential
	}
	for _, tc := range cases {
		node, ok := graphs.graph.Node(tc.id)
		if !ok {
			t.Fatalf("expected %s in graph", tc.id)
		}
		origin := originOf(node)
		if origin.ArtifactURL != tc.want {
			t.Errorf("%s artifact origin = %q, want %q", tc.id, origin.ArtifactURL, tc.want)
		}
		if origin.Repository != "" {
			t.Errorf("%s asserted a repository %q", tc.id, origin.Repository)
		}
		// ResolvedURL is a separate contract (the scorecard matcher resolves
		// repositories from it) and must keep carrying the raw lockfile value.
		if node.ResolvedURL == "" {
			t.Errorf("%s lost its ResolvedURL", tc.id)
		}
	}
}

// A v1 lockfile repeats a package at every place it is installed, and the
// copies can disagree: one nested under a package pinned to a private mirror,
// one at the top level from the public registry. They share a name and version,
// so they become one graph node, and the node must not report whichever copy
// the traversal reached first.
func TestNPMv1DuplicateEntriesReconcileOrigin(t *testing.T) {
	projectDir := t.TempDir()
	lockfile := `{
      "name": "demo",
      "version": "1.0.0",
      "lockfileVersion": 1,
      "dependencies": {
        "a-first": {
          "version": "1.0.0",
          "resolved": "https://registry.npmjs.org/a-first/-/a-first-1.0.0.tgz",
          "dependencies": {
            "disputed": {"version": "2.0.0", "resolved": "https://npm.corp/mirror/disputed/-/disputed-2.0.0.tgz"},
            "agreed": {"version": "3.0.0", "resolved": "https://registry.npmjs.org/agreed/-/agreed-3.0.0.tgz"}
          }
        },
        "z-last": {
          "version": "1.0.0",
          "resolved": "https://registry.npmjs.org/z-last/-/z-last-1.0.0.tgz",
          "dependencies": {
            "disputed": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/disputed/-/disputed-2.0.0.tgz"},
            "agreed": {"version": "3.0.0", "resolved": "https://registry.npmjs.org/agreed/-/agreed-3.0.0.tgz"}
          }
        }
      }
    }`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatal(err)
	}

	// Repeat: the traversal walks maps, so an order-dependent result would
	// show up as a different answer between runs rather than a stable wrong one.
	for range 25 {
		graphs, err := depGraphFromNPMLockfile(projectDir)
		if err != nil {
			t.Fatalf("depGraphFromNPMLockfile() error = %v", err)
		}

		disputed, ok := graphs.graph.Node("disputed@2.0.0")
		if !ok {
			t.Fatal("expected disputed@2.0.0 in graph")
		}
		if origin := originOf(disputed); !origin.Empty() {
			t.Fatalf("disputed origin = %+v, want none: its two copies name different locations", origin)
		}

		agreed, ok := graphs.graph.Node("agreed@3.0.0")
		if !ok {
			t.Fatal("expected agreed@3.0.0 in graph")
		}
		const want = "https://registry.npmjs.org/agreed/-/agreed-3.0.0.tgz"
		if got := originOf(agreed).ArtifactURL; got != want {
			t.Fatalf("agreed origin = %q, want %q: its copies agree", got, want)
		}
	}
}
