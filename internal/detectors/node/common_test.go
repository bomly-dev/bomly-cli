package node_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/npm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn"
	"github.com/bomly-dev/bomly-sdk"
)

func TestAnnotateScopesFromPackageJSON(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0"
  },
  "devDependencies": {
    "vitest": "^2.0.0"
  }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	depsGraph := sdk.New()
	root := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "demo-app", Version: "1.0.0"}})
	react := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "react", Version: "18.2.0"}})
	scheduler := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "scheduler", Version: "0.23.0"}})
	vitest := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "vitest", Version: "2.0.0"}})
	chai := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "chai", Version: "5.1.0"}})
	for _, pkg := range []*sdk.Dependency{root, react, scheduler, vitest, chai} {
		if err := depsGraph.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	for _, edge := range [][2]string{
		{root.ID, react.ID},
		{root.ID, vitest.ID},
		{react.ID, scheduler.ID},
		{vitest.ID, chai.ID},
	} {
		if err := depsGraph.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add dependency %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	if err := node.AnnotateScopesFromPackageJSON(projectDir, depsGraph); err != nil {
		t.Fatalf("AnnotateScopesFromPackageJSON() error = %v", err)
	}

	if string(react.PrimaryScope()) != string(sdk.ScopeRuntime) || string(scheduler.PrimaryScope()) != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scopes for runtime chain, got react=%q scheduler=%q", string(react.PrimaryScope()), string(scheduler.PrimaryScope()))
	}
	if string(vitest.PrimaryScope()) != string(sdk.ScopeDevelopment) || string(chai.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scopes for dev chain, got vitest=%q chai=%q", string(vitest.PrimaryScope()), string(chai.PrimaryScope()))
	}
}

func TestAnnotateScopesFromPackageJSON_DevelopmentFilterExcludesRuntime(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0"
  },
  "devDependencies": {
    "vitest": "^2.0.0"
  }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	depsGraph := sdk.New()
	root := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "demo-app", Version: "1.0.0"}})
	react := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "react", Version: "18.2.0"}})
	vitest := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "vitest", Version: "2.0.0"}})
	shared := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "shared", Version: "1.0.0"}})
	for _, pkg := range []*sdk.Dependency{root, react, vitest, shared} {
		if err := depsGraph.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	for _, edge := range [][2]string{
		{root.ID, react.ID},
		{root.ID, vitest.ID},
		{react.ID, shared.ID},
		{vitest.ID, shared.ID},
	} {
		if err := depsGraph.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add dependency %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	if err := node.AnnotateScopesFromPackageJSON(projectDir, depsGraph); err != nil {
		t.Fatalf("AnnotateScopesFromPackageJSON() error = %v", err)
	}
	filtered, err := sdk.FilterGraphByScope(depsGraph, sdk.ScopeDevelopment)
	if err != nil {
		t.Fatalf("FilterGraphByScope() error = %v", err)
	}
	if _, ok := filtered.Node(vitest.ID); !ok {
		t.Fatalf("expected development dependency to remain: %s", filtered.PrettyString())
	}
	if _, ok := filtered.Node(react.ID); ok {
		t.Fatalf("expected runtime dependency to be filtered: %s", filtered.PrettyString())
	}
	if _, ok := filtered.Node(shared.ID); ok {
		t.Fatalf("expected runtime-primary shared dependency to be filtered: %s", filtered.PrettyString())
	}
}

func TestDepGraphFromNPMJSON(t *testing.T) {
	raw := []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0",
      "dependencies": {
        "loose-envify": {
          "version": "1.4.0"
        }
      }
    },
    "zod": {
      "version": "3.23.0"
    }
  }
}`)

	g, err := node.DepGraphFromNPMJSON(raw)
	if err != nil {
		t.Fatalf("DepGraphFromNPMJSON() error = %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d", g.Size())
	}
}

func TestDepGraphFromPNPMJSON(t *testing.T) {
	raw := []byte(`[
  {
    "name": "demo-app",
    "version": "1.0.0",
    "dependencies": {
      "react": {
        "version": "18.2.0",
        "dependencies": {
          "loose-envify": {
            "version": "1.4.0"
          }
        }
      }
    }
  }
]`)

	g, err := node.DepGraphFromPNPMJSON(raw)
	if err != nil {
		t.Fatalf("DepGraphFromPNPMJSON() error = %v", err)
	}
	if g.Size() != 3 {
		t.Fatalf("expected 3 packages, got %d", g.Size())
	}
}

func TestDepGraphFromYarnJSON(t *testing.T) {
	raw := []byte(`{"type":"tree","data":{"type":"list","trees":[{"name":"react@18.2.0","children":[{"name":"loose-envify@1.4.0","children":[]}]}]}}`)

	g, err := node.DepGraphFromYarnJSON(raw)
	if err != nil {
		t.Fatalf("DepGraphFromYarnJSON() error = %v", err)
	}
	if g.Size() != 3 {
		t.Fatalf("expected 3 packages, got %d", g.Size())
	}
}

func TestDepGraphFromNPMLockfileV1(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "react": {
      "version": "18.2.0",
      "dependencies": {
        "loose-envify": {
          "version": "1.4.0"
        }
      }
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	g, err := resolveTestGraph(t, npm.LockfileDetector{}, projectDir)
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile() error = %v", err)
	}
	if g.Size() != 3 {
		t.Fatalf("expected 3 packages, got %d", g.Size())
	}
}

func TestDepGraphFromNPMLockfileV3(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo-app",
      "version": "1.0.0",
      "dependencies": {
        "react": "18.2.0"
      }
    },
    "node_modules/react": {
      "version": "18.2.0",
      "dependencies": {
        "loose-envify": "1.4.0"
      }
    },
    "node_modules/loose-envify": {
      "version": "1.4.0"
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	g, err := resolveTestGraph(t, npm.LockfileDetector{}, projectDir)
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile() error = %v", err)
	}
	if g.Size() != 3 {
		t.Fatalf("expected 3 packages, got %d", g.Size())
	}
}

func TestDepGraphFromPNPMLockfile(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0"
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "pnpm-lock.yaml"), []byte(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        version: 18.2.0
packages:
  react@18.2.0:
    dependencies:
      loose-envify: 1.4.0
  loose-envify@1.4.0: {}
`), 0o644); err != nil {
		t.Fatalf("write pnpm-lock.yaml: %v", err)
	}

	g, err := resolveTestGraph(t, pnpm.LockfileDetector{}, projectDir)
	if err != nil {
		t.Fatalf("depGraphFromPNPMLockfile() error = %v", err)
	}
	if g.Size() != 3 {
		t.Fatalf("expected 3 packages, got %d", g.Size())
	}
}

func TestDepGraphFromYarnLockfile(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0"
  }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "yarn.lock"), []byte(`react@^18.2.0:
  version "18.2.0"
  dependencies:
    loose-envify "^1.4.0"

loose-envify@^1.4.0:
  version "1.4.0"
`), 0o644); err != nil {
		t.Fatalf("write yarn.lock: %v", err)
	}

	g, err := resolveTestGraph(t, yarn.LockfileDetector{}, projectDir)
	if err != nil {
		t.Fatalf("depGraphFromYarnLockfile() error = %v", err)
	}
	if g.Size() != 3 {
		t.Fatalf("expected 3 packages, got %d", g.Size())
	}
}

func TestLockfileDetectorsDoNotRequirePackageManagerBinaries(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	for name, detector := range map[string]sdk.Detector{
		"npm":  npm.LockfileDetector{},
		"pnpm": pnpm.LockfileDetector{},
		"yarn": yarn.LockfileDetector{},
	} {
		if err := detector.Ready(context.Background(), sdk.DetectionRequest{}); err != nil {
			t.Fatalf("expected %s lockfile detector to be ready without package manager on PATH: %v", name, err)
		}
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo-app", "version": "1.0.0"}
  }
}`), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	detector := npm.LockfileDetector{}
	applicable, err := detector.Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatal("expected npm lockfile detector to be applicable when package-lock.json exists")
	}
}

func TestLockfileDetectorRequiresLockfile(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"demo-app","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	detector := npm.LockfileDetector{}
	applicable, err := detector.Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if applicable {
		t.Fatal("expected npm lockfile detector to be inapplicable without package-lock.json")
	}
}

func TestMergedNPMDetectorInstallFirstDisabledByConfig(t *testing.T) {
	disabled := false
	detector := npm.Detector{Config: node.StrategyConfig{InstallFirst: &disabled}}
	// With installFirst disabled, Install must be a no-op even when the host
	// requested install-first execution: no npm subprocess runs (the test has
	// no project dir, so a real install attempt would fail loudly).
	if err := detector.Install(context.Background(), sdk.DetectionRequest{InstallFirst: true}); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
}

func TestMergedNPMDetectorRejectsUnknownStrategy(t *testing.T) {
	detector := npm.Detector{Config: node.StrategyConfig{Strategy: []string{"lockfile", "bogus"}}}
	if err := detector.Ready(context.Background(), sdk.DetectionRequest{}); err == nil || !strings.Contains(err.Error(), `unknown strategy action "bogus"`) {
		t.Fatalf("expected unknown-strategy error from Ready, got %v", err)
	}
	if _, err := detector.Applicable(context.Background(), sdk.DetectionRequest{}); err == nil {
		t.Fatal("expected unknown-strategy error from Applicable")
	}
	if _, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{}); err == nil {
		t.Fatal("expected unknown-strategy error from ResolveGraph")
	}
}

func TestMergedNPMDetectorLockfileFirst(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo-app",
      "version": "1.0.0",
      "dependencies": {
        "react": "18.2.0"
      }
    },
    "node_modules/react": {
      "version": "18.2.0"
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	detector := npm.Detector{}
	applicable, err := detector.Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil || !applicable {
		t.Fatalf("expected merged npm detector to be applicable, got %v / %v", applicable, err)
	}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if result.Technique != sdk.LockfileTechnique {
		t.Fatalf("expected the winning lockfile strategy to stamp its technique, got %q", result.Technique)
	}
	if result.Graphs == nil || result.Graphs.Len() == 0 {
		t.Fatal("expected graphs from the lockfile strategy")
	}
}

func resolveTestGraph(t *testing.T, detector sdk.Detector, projectDir string) (*sdk.Graph, error) {
	t.Helper()
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		return nil, err
	}
	return result.Graphs.ConsolidatedGraph()
}

// resolveTestWarnings resolves a project and returns the warnings the detector
// reported alongside its graphs.
func resolveTestWarnings(t *testing.T, detector sdk.Detector, projectDir string) []sdk.DetectorWarning {
	t.Helper()
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	return result.Warnings
}

func TestPNPMLockfileDetectorReportsPackageManagerWarnings(t *testing.T) {
	projectDir := t.TempDir()
	// A pnpm 6.0 lockfile with a pnpm 11 pin: pnpm 11 migrates the format, so a
	// frozen-lockfile CI install fails even though this parse succeeds.
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "packageManager": "pnpm@11.0.0"
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "pnpm-lock.yaml"), []byte(`lockfileVersion: '6.0'
dependencies:
  react:
    specifier: ^18.2.0
    version: 18.2.0
packages:
  /react@18.2.0:
    dev: false
`), 0o644); err != nil {
		t.Fatalf("write pnpm-lock.yaml: %v", err)
	}

	warnings := resolveTestWarnings(t, pnpm.LockfileDetector{}, projectDir)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %+v", warnings)
	}
	if warnings[0].Type != sdk.DetectorWarningPackageManager ||
		warnings[0].Code != sdk.DetectorWarningCodeLockfileFormat ||
		warnings[0].Source != "pnpm" ||
		warnings[0].Manifest != "pnpm-lock.yaml" {
		t.Fatalf("unexpected warning: %+v", warnings[0])
	}
	if warnings[0].DegradesCoverage() {
		t.Fatal("a package-manager warning must not claim degraded coverage")
	}
}

func TestYarnLockfileDetectorReportsBerryFormatWarning(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "packageManager": "yarn@1.22.22",
  "dependencies": {"react": "^18.2.0"}
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "yarn.lock"), []byte(`__metadata:
  version: 8
  cacheKey: 10

"react@npm:^18.2.0":
  version: 18.2.0
`), 0o644); err != nil {
		t.Fatalf("write yarn.lock: %v", err)
	}

	warnings := resolveTestWarnings(t, yarn.LockfileDetector{}, projectDir)
	if len(warnings) != 1 || warnings[0].Code != sdk.DetectorWarningCodeLockfileFormat {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}
}

func TestLockfileDetectorsLeaveConsistentProjectsUnannotated(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "packageManager": "npm@10.9.0"
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
  "name": "demo-app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo-app", "dependencies": {"react": "^18.2.0"}},
    "node_modules/react": {"version": "18.2.0"}
  }
}`), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	if warnings := resolveTestWarnings(t, npm.LockfileDetector{}, projectDir); len(warnings) != 0 {
		t.Fatalf("expected no warnings for a consistent project, got %+v", warnings)
	}
}
