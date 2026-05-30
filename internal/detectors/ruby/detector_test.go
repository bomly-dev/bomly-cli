package ruby

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixtureProject(t *testing.T) {
	detector := Detector{WorkingDir: "testdata/project"}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     "testdata/project",
		PackageManager:  sdk.PackageManagerBundler,
		Ecosystem:       sdk.EcosystemRuby,
		ExecutionTarget: sdk.ExecutionTarget{Location: "testdata/project"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	rack, ok := g.Node("rack@3.1.8")
	if !ok {
		t.Fatal("expected rack package")
	}
	if string(rack.PrimaryScope()) != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope, got %q", rack.PrimaryScope())
	}
	rake, ok := g.Node("rake@13.2.1")
	if !ok {
		t.Fatal("expected rake package")
	}
	if string(rake.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scope, got %q", rake.PrimaryScope())
	}
}

func TestDepGraphFromLock(t *testing.T) {
	raw := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    rake (13.2.1)
    rails (7.1.0)
      activesupport (>= 7.1.0)
      rake (>= 12.2)
    activesupport (7.1.0)

DEPENDENCIES
  rails
  rake
`)

	g, err := depGraphFromLock(raw, map[string]sdk.Scope{
		"rake":  sdk.ScopeDevelopment,
		"rails": sdk.ScopeRuntime,
	})
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d", g.Size())
	}

	rake, ok := g.Node("rake@13.2.1")
	if !ok {
		t.Fatal("expected rake package")
	}
	if got := string(rake.PrimaryScope()); got != string(sdk.ScopeRuntime) {
		t.Fatalf("expected rake scope runtime, got %q", got)
	}

	activeSupport, ok := g.Node("activesupport@7.1.0")
	if !ok {
		t.Fatal("expected activesupport package")
	}
	if got := string(activeSupport.PrimaryScope()); got != string(sdk.ScopeRuntime) {
		t.Fatalf("expected activesupport scope runtime, got %q", got)
	}
}

func TestParseGemfileScopes(t *testing.T) {
	tempDir := t.TempDir()
	gemfilePath := filepath.Join(tempDir, "Gemfile")
	content := []byte("gem 'rails'\n\ngroup :development, :test do\n  gem 'rubocop'\nend\n")
	if err := os.WriteFile(gemfilePath, content, 0o644); err != nil {
		t.Fatalf("write Gemfile: %v", err)
	}

	scopes, err := parseGemfileScopes(gemfilePath)
	if err != nil {
		t.Fatalf("parseGemfileScopes() error = %v", err)
	}
	if scopes["rails"] != sdk.ScopeRuntime {
		t.Fatalf("expected rails runtime scope, got %q", scopes["rails"])
	}
	if scopes["rubocop"] != sdk.ScopeDevelopment {
		t.Fatalf("expected rubocop development scope, got %q", scopes["rubocop"])
	}
}
