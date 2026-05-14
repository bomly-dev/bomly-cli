package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
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
	if _, ok := pkg.Metadata[sdk.MetadataKeyNPM]; ok {
		t.Fatalf("expected array engines to be ignored, got metadata: %+v", pkg.Metadata)
	}
}

func TestResolveNPMLockDependencyIDFallsBackDeterministically(t *testing.T) {
	lockfile := npmPackageLock{
		Packages: map[string]npmLockPackage{
			"node_modules/z-parent/node_modules/shared": {
				Name:    "shared",
				Version: "1.2.3",
			},
			"node_modules/a-parent/node_modules/shared": {
				Name:    "shared",
				Version: "1.2.3",
			},
		},
	}
	pathToID := map[string]string{
		"node_modules/z-parent/node_modules/shared": "pkg:npm/shared@1.2.3-z",
		"node_modules/a-parent/node_modules/shared": "pkg:npm/shared@1.2.3-a",
	}

	got, ok := resolveNPMLockDependencyID("node_modules/example", "shared", "1.2.3", lockfile, pathToID)
	if !ok {
		t.Fatal("expected fallback dependency resolution to succeed")
	}
	if got != "pkg:npm/shared@1.2.3-a" {
		t.Fatalf("expected lexicographically first package path to win, got %q", got)
	}
}

func TestResolveNPMLockDependencyIDResolvesHoistedFromTopLevelParent(t *testing.T) {
	lockfile := npmPackageLock{
		Packages: map[string]npmLockPackage{
			"node_modules/cliui/node_modules/string-width": {
				Name:    "string-width",
				Version: "3.1.0",
			},
			"node_modules/string-width": {
				Name:    "string-width",
				Version: "2.1.1",
			},
		},
	}
	pathToID := map[string]string{
		"node_modules/cliui/node_modules/string-width": "pkg:npm/string-width@3.1.0",
		"node_modules/string-width":                    "pkg:npm/string-width@2.1.1",
	}

	got, ok := resolveNPMLockDependencyID("node_modules/wide-align", "string-width", "^1.0.2 || 2", lockfile, pathToID)
	if !ok {
		t.Fatal("expected hoisted dependency resolution to succeed")
	}
	if got != "pkg:npm/string-width@2.1.1" {
		t.Fatalf("expected top-level hoisted package to be selected, got %q", got)
	}
}
