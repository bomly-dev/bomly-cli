package ruby

import (
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

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

	g, err := depGraphFromLock(raw, map[string]model.Scope{
		"rake":  model.ScopeDevelopment,
		"rails": model.ScopeRuntime,
	})
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d", g.Size())
	}

	rake, ok := g.Package("rake@13.2.1")
	if !ok {
		t.Fatal("expected rake package")
	}
	if got := rake.Scope; got != string(model.ScopeRuntime) {
		t.Fatalf("expected rake scope runtime, got %q", got)
	}

	activeSupport, ok := g.Package("activesupport@7.1.0")
	if !ok {
		t.Fatal("expected activesupport package")
	}
	if got := activeSupport.Scope; got != string(model.ScopeRuntime) {
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
	if scopes["rails"] != model.ScopeRuntime {
		t.Fatalf("expected rails runtime scope, got %q", scopes["rails"])
	}
	if scopes["rubocop"] != model.ScopeDevelopment {
		t.Fatalf("expected rubocop development scope, got %q", scopes["rubocop"])
	}
}
