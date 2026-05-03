package githubactions

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixtureProject(t *testing.T) {
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), model.DetectionRequest{
		ProjectPath:     "testdata/project",
		PackageManager:  model.PackageManagerGitHubActions,
		Ecosystem:       model.EcosystemGitHub,
		ExecutionTarget: model.ExecutionTarget{Location: "testdata/project"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if _, ok := g.Package("actions:checkout@v4"); !ok {
		t.Fatal("expected actions/checkout package")
	}
	if _, ok := g.Package("actions:cache@v4"); !ok {
		t.Fatal("expected actions/cache package")
	}
}

func TestDepGraphFromRepository(t *testing.T) {
	projectDir := t.TempDir()
	workflowDir := filepath.Join(projectDir, ".github", "workflows")
	actionDir := filepath.Join(projectDir, ".github", "actions", "local-setup")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflow dir: %v", err)
	}
	if err := os.MkdirAll(actionDir, 0o755); err != nil {
		t.Fatalf("create action dir: %v", err)
	}

	workflow := []byte("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/local-setup\n  deploy:\n    uses: ./.github/workflows/reusable.yml\n")
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), workflow, 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	reusable := []byte("jobs:\n  nested:\n    steps:\n      - uses: actions/setup-java@v5\n")
	if err := os.WriteFile(filepath.Join(workflowDir, "reusable.yml"), reusable, 0o644); err != nil {
		t.Fatalf("write reusable workflow: %v", err)
	}
	action := []byte("runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n")
	if err := os.WriteFile(filepath.Join(actionDir, "action.yml"), action, 0o644); err != nil {
		t.Fatalf("write action manifest: %v", err)
	}

	g, err := depGraphFromRepository(projectDir)
	if err != nil {
		t.Fatalf("depGraphFromRepository() error = %v", err)
	}
	if g.Size() != 6 {
		t.Fatalf("expected 6 packages, got %d", g.Size())
	}

	cache, ok := g.Package("actions:cache@v4")
	if !ok {
		t.Fatal("expected actions/cache package")
	}
	if got := cache.Scope; got != string(model.ScopeRuntime) {
		t.Fatalf("expected runtime scope, got %q", got)
	}

	localAction, ok := g.Package("action:.github/actions/local-setup")
	if !ok {
		t.Fatal("expected local action package")
	}
	deps, err := g.Dependencies(localAction.ID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0].ID != "actions:cache@v4" {
		t.Fatalf("expected local action to depend on actions/cache, got %#v", deps)
	}
	workflowNode, ok := g.Package("workflow:.github/workflows/ci.yml")
	if !ok {
		t.Fatal("expected ci workflow package")
	}
	workflowDeps, err := g.Dependencies(workflowNode.ID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(workflowDeps) != 3 {
		t.Fatalf("expected 3 workflow dependencies, got %d", len(workflowDeps))
	}
}
