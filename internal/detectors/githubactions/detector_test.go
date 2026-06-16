package githubactions

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixtureProject(t *testing.T) {
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     "testdata/project",
		PackageManager:  sdk.PackageManagerGitHubActions,
		Ecosystem:       sdk.EcosystemGitHub,
		ExecutionTarget: sdk.ExecutionTarget{Location: "testdata/project"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if _, ok := g.Node("actions:checkout@v4"); !ok {
		t.Fatal("expected actions/checkout package")
	}
	if _, ok := g.Node("actions:cache@v4"); !ok {
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

	cache, ok := g.Node("actions:cache@v4")
	if !ok {
		t.Fatal("expected actions/cache package")
	}
	if got := string(cache.PrimaryScope()); got != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope, got %q", got)
	}

	localAction, ok := g.Node("action:.github/actions/local-setup")
	if !ok {
		t.Fatal("expected local action package")
	}
	deps, err := g.DirectDependencies(localAction.ID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0].ID != "actions:cache@v4" {
		t.Fatalf("expected local action to depend on actions/cache, got %#v", deps)
	}
	workflowNode, ok := g.Node("workflow:.github/workflows/ci.yml")
	if !ok {
		t.Fatal("expected ci workflow package")
	}
	workflowDeps, err := g.DirectDependencies(workflowNode.ID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(workflowDeps) != 3 {
		t.Fatalf("expected 3 workflow dependencies, got %d", len(workflowDeps))
	}
}

func TestDetectorResolveGraphAttachesUsesLineLocations(t *testing.T) {
	projectDir := t.TempDir()
	workflowDir := filepath.Join(projectDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflow dir: %v", err)
	}
	workflow := []byte("name: CI\njobs:\n  build:\n    steps:\n      - name: Review dependencies\n        uses: actions/dependency-review-action@v5\n      - uses: github/codeql-action/upload-sarif@v4\n")
	if err := os.WriteFile(filepath.Join(workflowDir, "guard.yml"), workflow, 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	result, err := (Detector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     projectDir,
		PackageManager:  sdk.PackageManagerGitHubActions,
		Ecosystem:       sdk.EcosystemGitHub,
		ExecutionTarget: sdk.ExecutionTarget{Location: projectDir},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	dependencyReview, ok := g.Node("actions:dependency-review-action@v5")
	if !ok {
		t.Fatal("expected actions/dependency-review-action package")
	}
	if len(dependencyReview.Locations) != 1 {
		t.Fatalf("dependency-review-action locations = %#v, want one location", dependencyReview.Locations)
	}
	loc := dependencyReview.Locations[0]
	if loc.RealPath != ".github/workflows/guard.yml" || loc.AccessPath != ".github/workflows/guard.yml" {
		t.Fatalf("location path = %#v, want workflow manifest path", loc)
	}
	if loc.Position == nil || loc.Position.File != ".github/workflows/guard.yml" || loc.Position.Line != 6 || loc.Position.Column == 0 {
		t.Fatalf("location position = %#v, want workflow uses line with column", loc.Position)
	}

	codeql, ok := g.Node("github:codeql-action/upload-sarif@v4")
	if !ok {
		t.Fatal("expected github/codeql-action/upload-sarif package")
	}
	if len(codeql.Locations) != 1 || codeql.Locations[0].Position == nil || codeql.Locations[0].Position.Line != 7 {
		t.Fatalf("codeql action locations = %#v, want line 7", codeql.Locations)
	}
}
