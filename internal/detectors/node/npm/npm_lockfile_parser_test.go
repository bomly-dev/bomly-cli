package npm

import (
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestNPMLockfileParserAllowsArrayEngines(t *testing.T) {
	projectDir := t.TempDir()
	lockfile := []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo-app",
      "version": "1.0.0",
      "dependencies": {
        "benchmark": "1.0.0"
      }
    },
    "node_modules/benchmark": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/benchmark/-/benchmark-1.0.0.tgz",
      "integrity": "sha512-example",
      "engines": [
        "node",
        "rhino"
      ]
    }
  }
}`)
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), lockfile, 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	graph, err := depGraphFromNPMLockfile(projectDir)
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile() error = %v", err)
	}
	pkg, ok := graph.Package("benchmark@1.0.0")
	if !ok {
		t.Fatalf("expected benchmark@1.0.0 package")
	}
	if _, ok := pkg.Metadata[model.MetadataKeyNPM]; ok {
		t.Fatalf("expected array engines to be ignored, got metadata: %+v", pkg.Metadata)
	}
}
