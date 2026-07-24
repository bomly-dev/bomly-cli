package python

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzDepGraphFromPoetryLock(f *testing.F) {
	f.Add([]byte("[[package]]\nname = \"requests\"\nversion = \"2.32.0\"\ngroups = [\"main\"]\n"))
	f.Add([]byte("[[package]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		dir := t.TempDir()
		lockPath := filepath.Join(dir, "poetry.lock")
		if err := os.WriteFile(lockPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[tool.poetry]\nname = \"fuzz-root\"\nversion = \"1.0.0\"\n[tool.poetry.dependencies]\nrequests = \"*\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		graph, err := depGraphFromPoetryLock(lockPath, dir)
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}

func FuzzDepGraphFromUVLock(f *testing.F) {
	f.Add([]byte("[[package]]\nname = \"root\"\nversion = \"1.0.0\"\nsource = { editable = \".\" }\ndependencies = [{ name = \"dep\" }]\n[[package]]\nname = \"dep\"\nversion = \"2.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"))
	f.Add([]byte("[[package]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		path := filepath.Join(t.TempDir(), "uv.lock")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		graph, err := depGraphFromUVLock(path)
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}

func FuzzDepGraphFromPipfileLock(f *testing.F) {
	f.Add([]byte(`{"default":{"requests":{"version":"==2.32.0"}},"develop":{"pytest":{"version":"==8.0.0"}}}`))
	f.Add([]byte(`{"default":`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		path := filepath.Join(t.TempDir(), "Pipfile.lock")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		graph, err := depGraphFromPipfileLock(path)
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
