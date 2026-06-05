package yarn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestYarnLockfileParserSkipsUnreachableEntries(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "left-pad": "^1.3.0"
  }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "yarn.lock"), []byte(`left-pad@^1.3.0:
  version "1.3.0"

bcrypt-pbkdf@^1.0.0:
  version "1.0.2"

tweetnacl@^0.14.0:
  version "0.14.5"
`), 0o644); err != nil {
		t.Fatalf("write yarn.lock: %v", err)
	}

	graph, err := depGraphFromYarnLockfile(projectDir)
	if err != nil {
		t.Fatalf("depGraphFromYarnLockfile() error = %v", err)
	}
	if graph.Size() != 2 {
		t.Fatalf("expected only root + reachable dependency packages, got %d", graph.Size())
	}
	if _, ok := graph.Node("bcrypt-pbkdf@1.0.2"); ok {
		t.Fatal("expected unreachable bcrypt-pbkdf entry to be excluded")
	}
	if _, ok := graph.Node("tweetnacl@0.14.5"); ok {
		t.Fatal("expected unreachable tweetnacl entry to be excluded")
	}
	roots := graph.Roots()
	if len(roots) != 1 {
		t.Fatalf("expected single root package, got %d", len(roots))
	}
	if roots[0] == nil || roots[0].ID != "demo-app@1.0.0" {
		t.Fatalf("expected app root demo-app@1.0.0, got %#v", roots[0])
	}
}
