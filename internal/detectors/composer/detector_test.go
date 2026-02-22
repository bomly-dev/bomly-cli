package composer

import (
	"testing"

	"github.com/bomly/bomly-cli/internal/detectors"
)

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

	shared, ok := g.Package("vendor:shared@3.4.5")
	if !ok {
		t.Fatal("expected shared package to exist")
	}
	if got := shared.Scope; got != string(detectors.ScopeRuntime) {
		t.Fatalf("expected shared scope runtime, got %q", got)
	}

	devTool, ok := g.Package("vendor:dev-tool@4.0.0")
	if !ok {
		t.Fatal("expected dev package to exist")
	}
	if got := devTool.Scope; got != string(detectors.ScopeDevelopment) {
		t.Fatalf("expected dev package scope development, got %q", got)
	}
}
