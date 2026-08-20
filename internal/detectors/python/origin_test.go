package python

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

// originOf returns the origin a node publishes, or the zero value when it has
// none, so cases can compare plain structs.
// A package can be listed in both the default and develop groups. They become
// one node, so two groups naming different sources must cancel rather than
// publishing whichever group was processed first.
func TestPipenvGroupsReconcileOrigin(t *testing.T) {
	cases := []struct {
		name       string
		develop    string
		wantOrigin sdk.PackageOrigin
	}{
		{
			name:       "groups agree",
			develop:    "https://public.example/helper-1.0.0.tar.gz",
			wantOrigin: sdk.PackageOrigin{ArtifactURL: "https://public.example/helper-1.0.0.tar.gz"},
		},
		{name: "groups name different sources", develop: "https://mirror.corp/helper-1.0.0.tar.gz"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			lock := `{
      "_meta": {"hash": {"sha256": "x"}},
      "default": {"helper": {"version": "==1.0.0", "file": "https://public.example/helper-1.0.0.tar.gz"}},
      "develop": {"helper": {"version": "==1.0.0", "file": "` + tc.develop + `"}}
    }`
			path := filepath.Join(dir, "Pipfile.lock")
			if err := os.WriteFile(path, []byte(lock), 0o644); err != nil {
				t.Fatal(err)
			}

			graph, err := depGraphFromPipfileLock(path, "demo")
			if err != nil {
				t.Fatalf("depGraphFromPipfileLock() error = %v", err)
			}

			var checked int
			graph.WalkNodes(func(dep *sdk.Dependency) bool {
				if dep.Name != "helper" {
					return true
				}
				checked++
				if got := originOf(dep); got != tc.wantOrigin {
					t.Fatalf("origin = %+v, want %+v", got, tc.wantOrigin)
				}
				return true
			})
			if checked != 1 {
				t.Fatalf("found %d helper nodes, want 1", checked)
			}
		})
	}
}

func originOf(dep *sdk.Dependency) sdk.PackageOrigin {
	if dep == nil {
		return sdk.PackageOrigin{}
	}
	if origin := dep.Origin.Normalized(); origin != nil {
		return *origin
	}
	return sdk.PackageOrigin{}
}

// requireOrigin asserts the exact origin a named package asserts.
func requireOrigin(t *testing.T, graph *sdk.Graph, id string, want sdk.PackageOrigin) {
	t.Helper()
	node, ok := graph.Node(id)
	if !ok {
		t.Fatalf("expected %s in graph", id)
	}
	if got := originOf(node); got != want {
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
	requireOrigin(t, graph, "from-git@1.0.0", sdk.PackageOrigin{
		Repository: "https://github.com/example/from-git",
		Revision:   "9f8e7d6c5b4a3928176554433221100ffeeddcc0",
	})
	requireOrigin(t, graph, "from-url@2.0.0", sdk.PackageOrigin{
		ArtifactURL: "https://files.pythonhosted.org/packages/ab/from_url-2.0.0-py3-none-any.whl",
	})
	// An index root is not this package's origin, and a path is local.
	requireOrigin(t, graph, "from-registry@3.0.0", sdk.PackageOrigin{})
	requireOrigin(t, graph, "from-path@4.0.0", sdk.PackageOrigin{})
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

	requireOrigin(t, graph, "from-pypi@1.0.0", sdk.PackageOrigin{})
	// resolved_reference is the commit poetry locked; reference is the branch.
	requireOrigin(t, graph, "from-git@2.0.0", sdk.PackageOrigin{
		Repository: "https://github.com/example/from-git.git",
		Revision:   "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567",
	})
	requireOrigin(t, graph, "from-url@3.0.0", sdk.PackageOrigin{
		ArtifactURL: "https://files.pythonhosted.org/packages/cd/from_url-3.0.0.tar.gz",
	})
	requireOrigin(t, graph, "from-private-index@4.0.0", sdk.PackageOrigin{})
	requireOrigin(t, graph, "from-directory@5.0.0", sdk.PackageOrigin{})
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

	requireOrigin(t, graph, "from-pypi@1.0.0", sdk.PackageOrigin{})
	requireOrigin(t, graph, "from-git", sdk.PackageOrigin{
		Repository: "https://github.com/example/from-git.git",
		Revision:   "1f2e3d4c5b6a79880912a3b4c5d6e7f809172635",
	})
	requireOrigin(t, graph, "from-archive", sdk.PackageOrigin{
		ArtifactURL: "https://files.pythonhosted.org/packages/ef/from_archive-2.0.0.tar.gz",
	})
	requireOrigin(t, graph, "from-local", sdk.PackageOrigin{})
	requireOrigin(t, graph, "from-path", sdk.PackageOrigin{})
}

// pip records a PEP 610 direct_url.json for anything not installed from an
// index, distinguishing repositories, archives, and local directories.
func TestPipInspectOriginByDirectURLShape(t *testing.T) {
	cases := []struct {
		name      string
		directURL map[string]any
		want      sdk.PackageOrigin
	}{
		{name: "index install", directURL: nil},
		{
			name: "git checkout",
			directURL: map[string]any{
				"url":      "https://github.com/example/pkg.git",
				"vcs_info": map[string]any{"vcs": "git", "commit_id": "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e", "requested_revision": "main"},
			},
			want: sdk.PackageOrigin{Repository: "https://github.com/example/pkg.git", Revision: "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e"},
		},
		{
			name:      "archive URL",
			directURL: map[string]any{"url": "https://example.test/pkg-1.0.0-py3-none-any.whl", "archive_info": map[string]any{}},
			want:      sdk.PackageOrigin{ArtifactURL: "https://example.test/pkg-1.0.0-py3-none-any.whl"},
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
			if got := originOf(node); got != tc.want {
				t.Fatalf("origin = %+v, want %+v", got, tc.want)
			}
		})
	}
}
