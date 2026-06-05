package composer

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixtureProject(t *testing.T) {
	detector := Detector{WorkingDir: "testdata/project"}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     "testdata/project",
		PackageManager:  sdk.PackageManagerComposer,
		Ecosystem:       sdk.EcosystemPHP,
		ExecutionTarget: sdk.ExecutionTarget{Location: "testdata/project"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	runtimePkg, ok := g.Node("monolog:monolog@3.7.0")
	if !ok {
		t.Fatal("expected monolog package")
	}
	if string(runtimePkg.PrimaryScope()) != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope, got %q", string(runtimePkg.PrimaryScope()))
	}
	devPkg, ok := g.Node("phpunit:phpunit@11.4.3")
	if !ok {
		t.Fatal("expected phpunit package")
	}
	if string(devPkg.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scope, got %q", string(devPkg.PrimaryScope()))
	}
}

func TestDepGraphFromLock(t *testing.T) {
	raw := []byte(`{
  "packages": [
    {
      "name": "acme/app",
      "version": "1.0.0",
      "require": {
        "vendor/runtime": "^2.0"
      }
    },
    {
      "name": "vendor/runtime",
      "version": "2.1.0",
      "require": {
        "vendor/shared": "^3.0"
      }
    }
  ],
  "packages-dev": [
    {
      "name": "vendor/dev-tool",
      "version": "4.0.0",
      "require": {
        "vendor/shared": "^3.0"
      }
    },
    {
      "name": "vendor/shared",
      "version": "3.4.5",
      "require": {}
    }
  ]
}`)

	manifest := composerManifest{
		Require: map[string]string{
			"acme/app": "^1.0",
		},
		RequireDev: map[string]string{
			"vendor/dev-tool": "^4.0",
		},
	}

	g, err := depGraphFromLock(raw, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	if g.Size() != 5 {
		t.Fatalf("expected 5 packages, got %d", g.Size())
	}

	shared, ok := g.Node("vendor:shared@3.4.5")
	if !ok {
		t.Fatal("expected shared package to exist")
	}
	if got := string(shared.PrimaryScope()); got != string(sdk.ScopeRuntime) {
		t.Fatalf("expected shared scope runtime, got %q", got)
	}

	devTool, ok := g.Node("vendor:dev-tool@4.0.0")
	if !ok {
		t.Fatal("expected dev package to exist")
	}
	if got := string(devTool.PrimaryScope()); got != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected dev package scope development, got %q", got)
	}
}
