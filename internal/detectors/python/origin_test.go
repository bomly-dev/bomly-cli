package python

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

// requireOrigin asserts the exact origin a named package asserts.
func requireOrigin(t *testing.T, graph *sdk.Graph, id string, want detectors.Origin) {
	t.Helper()
	node, ok := graph.Node(id)
	if !ok {
		t.Fatalf("expected %s in graph", id)
	}
	if got := detectors.OriginFrom(node.Metadata); got != want {
		t.Errorf("%s origin = %+v, want %+v", id, got, want)
	}
}

func TestUVLockOriginBySourceType(t *testing.T) {
	dir := t.TempDir()
	lock := `
version = 1

[[package]]
name = "project"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "from-git"
version = "1.0.0"
source = { git = "https://github.com/example/from-git?rev=main#9f8e7d6c5b4a3928176554433221100ffeeddcc0" }

[[package]]
name = "from-url"
version = "2.0.0"
source = { url = "https://files.pythonhosted.org/packages/ab/from_url-2.0.0-py3-none-any.whl" }

[[package]]
name = "from-registry"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "from-path"
version = "4.0.0"
source = { path = "../vendor/from-path" }
`
	path := filepath.Join(dir, "uv.lock")
	if err := os.WriteFile(path, []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	graph, err := depGraphFromUVLock(path)
	if err != nil {
		t.Fatalf("depGraphFromUVLock() error = %v", err)
	}

	// The fragment carries the commit uv resolved; the "rev" query carries
	// what the manifest asked for.
	requireOrigin(t, graph, "from-git@1.0.0", detectors.Origin{
		VCSURL:      "https://github.com/example/from-git",
		VCSRevision: "9f8e7d6c5b4a3928176554433221100ffeeddcc0",
	})
	requireOrigin(t, graph, "from-url@2.0.0", detectors.Origin{
		ArtifactURL: "https://files.pythonhosted.org/packages/ab/from_url-2.0.0-py3-none-any.whl",
	})
	// An index root is not this package's origin, and a path is local.
	requireOrigin(t, graph, "from-registry@3.0.0", detectors.Origin{})
	requireOrigin(t, graph, "from-path@4.0.0", detectors.Origin{})
}

func TestPoetryLockOriginBySourceType(t *testing.T) {
	dir := t.TempDir()
	lock := `
[[package]]
name = "from-pypi"
version = "1.0.0"

[[package]]
name = "from-git"
version = "2.0.0"
[package.source]
type = "git"
url = "https://github.com/example/from-git.git"
reference = "main"
resolved_reference = "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567"

[[package]]
name = "from-url"
version = "3.0.0"
[package.source]
type = "url"
url = "https://files.pythonhosted.org/packages/cd/from_url-3.0.0.tar.gz"

[[package]]
name = "from-private-index"
version = "4.0.0"
[package.source]
type = "legacy"
url = "https://pypi.example.test/simple"
reference = "internal"

[[package]]
name = "from-directory"
version = "5.0.0"
[package.source]
type = "directory"
url = "../vendor/from-directory"
`
	lockPath := filepath.Join(dir, "poetry.lock")
	if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	graph, err := depGraphFromPoetryLock(lockPath, dir)
	if err != nil {
		t.Fatalf("depGraphFromPoetryLock() error = %v", err)
	}

	requireOrigin(t, graph, "from-pypi@1.0.0", detectors.Origin{})
	// resolved_reference is the commit poetry locked; reference is the branch.
	requireOrigin(t, graph, "from-git@2.0.0", detectors.Origin{
		VCSURL:      "https://github.com/example/from-git.git",
		VCSRevision: "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567",
	})
	requireOrigin(t, graph, "from-url@3.0.0", detectors.Origin{
		ArtifactURL: "https://files.pythonhosted.org/packages/cd/from_url-3.0.0.tar.gz",
	})
	requireOrigin(t, graph, "from-private-index@4.0.0", detectors.Origin{})
	requireOrigin(t, graph, "from-directory@5.0.0", detectors.Origin{})
}

func TestPipfileLockOriginBySourceType(t *testing.T) {
	dir := t.TempDir()
	lock := `{
      "default": {
        "from-pypi": {"version": "==1.0.0", "index": "pypi"},
        "from-git": {"git": "https://github.com/example/from-git.git", "ref": "1f2e3d4c5b6a79880912a3b4c5d6e7f809172635"},
        "from-archive": {"file": "https://files.pythonhosted.org/packages/ef/from_archive-2.0.0.tar.gz"},
        "from-local": {"file": "file:///workspace/wheels/from_local-3.0.0.whl"},
        "from-path": {"path": "../vendor/from-path"}
      },
      "develop": {}
    }`
	path := filepath.Join(dir, "Pipfile.lock")
	if err := os.WriteFile(path, []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	graph, err := depGraphFromPipfileLock(path, "demo")
	if err != nil {
		t.Fatalf("depGraphFromPipfileLock() error = %v", err)
	}

	requireOrigin(t, graph, "from-pypi@1.0.0", detectors.Origin{})
	requireOrigin(t, graph, "from-git", detectors.Origin{
		VCSURL:      "https://github.com/example/from-git.git",
		VCSRevision: "1f2e3d4c5b6a79880912a3b4c5d6e7f809172635",
	})
	requireOrigin(t, graph, "from-archive", detectors.Origin{
		ArtifactURL: "https://files.pythonhosted.org/packages/ef/from_archive-2.0.0.tar.gz",
	})
	requireOrigin(t, graph, "from-local", detectors.Origin{})
	requireOrigin(t, graph, "from-path", detectors.Origin{})
}

// pip records a PEP 610 direct_url.json for anything not installed from an
// index, distinguishing repositories, archives, and local directories.
func TestPipInspectOriginByDirectURLShape(t *testing.T) {
	cases := []struct {
		name      string
		directURL map[string]any
		want      detectors.Origin
	}{
		{name: "index install", directURL: nil},
		{
			name: "git checkout",
			directURL: map[string]any{
				"url":      "https://github.com/example/pkg.git",
				"vcs_info": map[string]any{"vcs": "git", "commit_id": "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e", "requested_revision": "main"},
			},
			want: detectors.Origin{VCSURL: "https://github.com/example/pkg.git", VCSRevision: "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e"},
		},
		{
			name:      "archive URL",
			directURL: map[string]any{"url": "https://example.test/pkg-1.0.0-py3-none-any.whl", "archive_info": map[string]any{}},
			want:      detectors.Origin{ArtifactURL: "https://example.test/pkg-1.0.0-py3-none-any.whl"},
		},
		{
			name:      "local directory",
			directURL: map[string]any{"url": "file:///workspace/pkg", "dir_info": map[string]any{}},
		},
		{
			name:      "mercurial checkout",
			directURL: map[string]any{"url": "https://hg.example.test/pkg", "vcs_info": map[string]any{"vcs": "hg", "commit_id": "9f8e7d6"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "pkg", Version: "1.0.0"}})
			setPipInspectOrigin(node, tc.directURL)
			if got := detectors.OriginFrom(node.Metadata); got != tc.want {
				t.Fatalf("origin = %+v, want %+v", got, tc.want)
			}
		})
	}
}
