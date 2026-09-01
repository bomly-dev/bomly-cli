package npm

import (
	"github.com/bomly-dev/bomly-sdk"
	"os"
	"path/filepath"
	"testing"
)

// originOf returns the origin a node publishes, or the zero value when it has
// none, so cases can compare plain structs.
func originOf(node sdk.GraphNode) sdk.DependencyOrigin {
	dep, ok := node.(*sdk.DependencyNode)
	if !ok || dep == nil {
		return sdk.DependencyOrigin{}
	}
	// Origins are gated on the way in, so the first entry is already
	// publishable; these cases assert on a single asserted origin.
	if len(dep.Origins) == 0 {
		return sdk.DependencyOrigin{}
	}
	return dep.Origins[0]
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
		origin := originOf(mustDep(t, node))
		if origin.ArtifactURL != tc.want {
			t.Errorf("%s artifact origin = %q, want %q", tc.id, origin.ArtifactURL, tc.want)
		}
		if origin.Repository != "" {
			t.Errorf("%s asserted a repository %q", tc.id, origin.Repository)
		}
		// ResolvedURL is a separate contract (the scorecard matcher resolves
		// repositories from it) and must keep carrying the raw lockfile value.
		if mustDep(t, node).ResolvedURL == "" {
			t.Errorf("%s lost its ResolvedURL", tc.id)
		}
	}
}

// A v1 lockfile repeats a package at every place it is installed, and the
// resolved string is each record's discriminator: positions pinning different
// tarballs stay distinct occurrences with their own origins, while positions
// pinning the same tarball fold as witnesses of one resolution.
func TestNPMv1DuplicateEntriesKeepDistinctResolutions(t *testing.T) {
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
            "shared": {"version": "2.0.0", "resolved": "https://npm.corp/mirror/shared/-/shared-2.0.0.tgz"},
            "agreed": {"version": "3.0.0", "resolved": "https://registry.npmjs.org/agreed/-/agreed-3.0.0.tgz"}
          }
        },
        "z-last": {
          "version": "1.0.0",
          "resolved": "https://registry.npmjs.org/z-last/-/z-last-1.0.0.tgz",
          "dependencies": {
            "shared": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/shared/-/shared-2.0.0.tgz"},
            "agreed": {"version": "3.0.0", "resolved": "https://registry.npmjs.org/agreed/-/agreed-3.0.0.tgz"}
          }
        }
      }
    }`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatal(err)
	}

	// Repeated: an order-dependent result shows up as instability.
	for range 25 {
		graphs, err := depGraphFromNPMLockfile(projectDir)
		if err != nil {
			t.Fatalf("depGraphFromNPMLockfile() error = %v", err)
		}
		sharedOrigins := map[string]int{}
		agreedNodes := 0
		graphs.graph.WalkNodes(func(dep sdk.GraphNode) bool {
			switch mustDep(t, dep).Name {
			case "shared":
				sharedOrigins[originOf(mustDep(t, dep)).ArtifactURL]++
			case "agreed":
				agreedNodes++
			}
			return true
		})
		if len(sharedOrigins) != 2 ||
			sharedOrigins["https://npm.corp/mirror/shared/-/shared-2.0.0.tgz"] != 1 ||
			sharedOrigins["https://registry.npmjs.org/shared/-/shared-2.0.0.tgz"] != 1 {
			t.Fatalf("shared occurrences = %v, want both resolutions distinct", sharedOrigins)
		}
		if agreedNodes != 1 {
			t.Fatalf("agreed nodes = %d, want identical resolutions folded", agreedNodes)
		}
	}
}

// Two package paths can install one name@version from different tarballs
// (nested overrides, mirror-pinned subtrees). The lockfile asserts two
// resolutions, so both stay as distinct occurrences with their own origins,
// and each path's edges attach to its own occurrence.
func TestNPMv3DuplicatePathsWithDifferentTarballsStayDistinct(t *testing.T) {
	projectDir := t.TempDir()
	lockfile := `{
      "name": "demo",
      "version": "1.0.0",
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "demo", "version": "1.0.0", "dependencies": {"a": "1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "dependencies": {"shared": "2.0.0"}},
        "node_modules/a/node_modules/shared": {"version": "2.0.0", "resolved": "https://npm.corp/mirror/shared/-/shared-2.0.0.tgz"},
        "node_modules/shared": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/shared/-/shared-2.0.0.tgz"}
      }
    }`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatal(err)
	}

	graphs, err := depGraphFromNPMLockfile(projectDir)
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile() error = %v", err)
	}

	origins := map[string]int{}
	graphs.graph.WalkNodes(func(dep sdk.GraphNode) bool {
		if mustDep(t, dep).Name == "shared" {
			origins[originOf(mustDep(t, dep)).ArtifactURL]++
		}
		return true
	})
	if len(origins) != 2 ||
		origins["https://registry.npmjs.org/shared/-/shared-2.0.0.tgz"] != 1 ||
		origins["https://npm.corp/mirror/shared/-/shared-2.0.0.tgz"] != 1 {
		t.Fatalf("shared occurrences = %v, want both tarballs as distinct nodes", origins)
	}
}

// mustDep narrows a graph node to the dependency node a case is asserting
// about, failing rather than panicking when the graph holds something else.
func mustDep(t testing.TB, node sdk.GraphNode) *sdk.DependencyNode {
	t.Helper()
	dep, ok := node.(*sdk.DependencyNode)
	if !ok {
		t.Fatalf("expected a dependency node, got %T", node)
	}
	return dep
}
