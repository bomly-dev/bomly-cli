package nuget

import (
	"context"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixtureProject(t *testing.T) {
	detector := Detector{WorkingDir: "testdata/project"}
	result, err := detector.ResolveGraph(context.Background(), model.DetectionRequest{
		ProjectPath:     "testdata/project",
		PackageManager:  model.PackageManagerNuGet,
		Ecosystem:       model.EcosystemDotNet,
		ExecutionTarget: model.ExecutionTarget{Location: "testdata/project"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	pkg, ok := g.Package("Newtonsoft.Json@13.0.3")
	if !ok {
		t.Fatal("expected Newtonsoft.Json package")
	}
	if pkg.PURL != "pkg:nuget/Newtonsoft.Json@13.0.3" {
		t.Fatalf("unexpected purl %q", pkg.PURL)
	}
}

func TestDepGraphFromLockMultiTarget(t *testing.T) {
	raw := []byte(`{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "abc",
        "dependencies": {"System.Text.Json": "8.0.0"}
      },
      "System.Text.Json": {
        "type": "Transitive",
        "resolved": "8.0.0"
      }
    },
    "net472": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "dependencies": {"System.Text.Json": "8.0.0"}
      }
    }
  }
}`)

	g, err := depGraphFromLock(raw)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	root, ok := g.Package("root")
	if !ok {
		t.Fatal("expected root package")
	}
	deps, err := g.Dependencies(root.ID)
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 1 || deps[0].Name != "Newtonsoft.Json" {
		t.Fatalf("expected root to depend on Newtonsoft.Json, got %#v", deps)
	}
	systemText, ok := g.Package("System.Text.Json@8.0.0")
	if !ok {
		t.Fatal("expected System.Text.Json package")
	}
	if systemText.Scope != string(model.ScopeRuntime) {
		t.Fatalf("expected transitive runtime scope, got %q", systemText.Scope)
	}
}

func TestDepGraphFromPackagesConfig(t *testing.T) {
	raw := []byte(`<packages><package id="NUnit" version="4.2.2" targetFramework="net48" /></packages>`)
	g, err := depGraphFromPackagesConfig(raw)
	if err != nil {
		t.Fatalf("depGraphFromPackagesConfig() error = %v", err)
	}
	pkg, ok := g.Package("NUnit@4.2.2")
	if !ok {
		t.Fatal("expected NUnit package")
	}
	if pkg.PURL != "pkg:nuget/NUnit@4.2.2" {
		t.Fatalf("unexpected purl %q", pkg.PURL)
	}
}
