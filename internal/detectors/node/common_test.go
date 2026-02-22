package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/model"
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

	if err := annotateScopesFromPackageJSON(projectDir, depsGraph); err != nil {
		t.Fatalf("annotateScopesFromPackageJSON() error = %v", err)
	}

	if react.Scope != string(detectors.ScopeRuntime) || scheduler.Scope != string(detectors.ScopeRuntime) {
		t.Fatalf("expected runtime scopes for runtime chain, got react=%q scheduler=%q", react.Scope, scheduler.Scope)
	}
	if vitest.Scope != string(detectors.ScopeDevelopment) || chai.Scope != string(detectors.ScopeDevelopment) {
		t.Fatalf("expected development scopes for dev chain, got vitest=%q chai=%q", vitest.Scope, chai.Scope)
	}
}
