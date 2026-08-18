package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
)

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
		origin := detectors.OriginFrom(node.Metadata)
		if origin.ArtifactURL != tc.want {
			t.Errorf("%s artifact origin = %q, want %q", tc.id, origin.ArtifactURL, tc.want)
		}
		if origin.VCSURL != "" {
			t.Errorf("%s asserted a repository %q", tc.id, origin.VCSURL)
		}
		// ResolvedURL is a separate contract (the scorecard matcher resolves
		// repositories from it) and must keep carrying the raw lockfile value.
		if node.ResolvedURL == "" {
			t.Errorf("%s lost its ResolvedURL", tc.id)
		}
	}
}
