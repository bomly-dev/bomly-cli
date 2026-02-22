package node_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/npm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn"
	model "github.com/bomly-dev/bomly-cli/sdk"
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

	depsGraph := model.New()
	root := model.NewPackage(model.Package{Ecosystem: "npm", Name: "demo-app", Version: "1.0.0"})
	react := model.NewPackage(model.Package{Ecosystem: "npm", Name: "react", Version: "18.2.0"})
	scheduler := model.NewPackage(model.Package{Ecosystem: "npm", Name: "scheduler", Version: "0.23.0"})
	vitest := model.NewPackage(model.Package{Ecosystem: "npm", Name: "vitest", Version: "2.0.0"})
	chai := model.NewPackage(model.Package{Ecosystem: "npm", Name: "chai", Version: "5.1.0"})
	for _, pkg := range []*model.Package{root, react, scheduler, vitest, chai} {
		if err := depsGraph.AddPackage(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	for _, edge := range [][2]string{
		{root.ID, react.ID},
		{root.ID, vitest.ID},
		{react.ID, scheduler.ID},
		{vitest.ID, chai.ID},
	} {
		if err := depsGraph.AddDependency(edge[0], edge[1]); err != nil {
			t.Fatalf("add dependency %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	if err := node.AnnotateScopesFromPackageJSON(projectDir, depsGraph); err != nil {
		t.Fatalf("AnnotateScopesFromPackageJSON() error = %v", err)
	}

	if react.Scope != string(model.ScopeRuntime) || scheduler.Scope != string(model.ScopeRuntime) {
		t.Fatalf("expected runtime scopes for runtime chain, got react=%q scheduler=%q", react.Scope, scheduler.Scope)
	}
	if vitest.Scope != string(model.ScopeDevelopment) || chai.Scope != string(model.ScopeDevelopment) {
		t.Fatalf("expected development scopes for dev chain, got vitest=%q chai=%q", vitest.Scope, chai.Scope)
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

	for name, detector := range map[string]model.Detector{
		"npm":  npm.LockfileDetector{},
		"pnpm": pnpm.LockfileDetector{},
		"yarn": yarn.LockfileDetector{},
	} {
		if !detector.Ready() {
			t.Fatalf("expected %s lockfile detector to be ready without package manager on PATH", name)
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
	applicable, err := detector.Applicable(context.Background(), model.DetectionRequest{ProjectPath: projectDir})
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
	applicable, err := detector.Applicable(context.Background(), model.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if applicable {
		t.Fatal("expected npm lockfile detector to be inapplicable without package-lock.json")
	}
}

func TestNPMDetectorInstallDelegatesToFallback(t *testing.T) {
	fallback := &installRecorderDetector{}
	detector := npm.LockfileDetector{Fallback: fallback}
	if err := detector.Install(context.Background(), model.DetectionRequest{}); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if fallback.called != 1 {
		t.Fatalf("expected fallback install to be called once, got %d", fallback.called)
	}
}

type installRecorderDetector struct {
	called int
}

func resolveTestGraph(t *testing.T, detector model.Detector, projectDir string) (*model.Graph, error) {
	t.Helper()
	result, err := detector.ResolveGraph(context.Background(), model.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		return nil, err
	}
	return result.Graphs.ConsolidatedGraph()
}

func (d *installRecorderDetector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{Name: "install-recorder"}
}

func (d *installRecorderDetector) PackageManagerSupport() []model.PackageManagerSupport {
	return nil
}

func (d *installRecorderDetector) Ready() bool {
	return true
}

func (d *installRecorderDetector) Applicable(context.Context, model.DetectionRequest) (bool, error) {
	return true, nil
}

func (d *installRecorderDetector) ResolveGraph(context.Context, model.DetectionRequest) (model.DetectionResult, error) {
	return model.DetectionResult{}, nil
}

func (d *installRecorderDetector) Install(context.Context, model.DetectionRequest) error {
	d.called++
	return nil
}
