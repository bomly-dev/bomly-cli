package cli

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/config"
)

func TestApplyStringOverride(t *testing.T) {
	value := "original"
	applyStringOverride(&value, "")
	if value != "original" {
		t.Fatalf("empty override changed value to %q", value)
	}

	applyStringOverride(&value, "updated")
	if value != "updated" {
		t.Fatalf("expected updated value, got %q", value)
	}
}

func TestCloneWithOverridesAppliesRecursiveDiscovery(t *testing.T) {
	adapter := &mcpOptionsAdapter{options: opts.NewOptions()}
	base := adapter.options.GetConfig()
	config.ApplyDefaults(&base)
	adapter.options.SetConfig(base)

	clone := adapter.cloneWithOverrides(mcpOverrides{
		Recursive: true,
		MaxDepth:  5,
		Exclude:   "apps/*, dist",
	})
	got := clone.GetConfig()
	if !got.Recursive {
		t.Fatal("expected recursive override to apply")
	}
	if got.MaxDepth != 5 {
		t.Fatalf("expected max depth 5, got %d", got.MaxDepth)
	}
	if len(got.ExcludePaths) != 2 || got.ExcludePaths[0] != "apps/*" || got.ExcludePaths[1] != "dist" {
		t.Fatalf("expected CSV exclude override, got %#v", got.ExcludePaths)
	}

	// Zero MaxDepth means "not set": the server's resolved default survives.
	clone = adapter.cloneWithOverrides(mcpOverrides{Recursive: true})
	if got := clone.GetConfig(); got.MaxDepth != base.MaxDepth {
		t.Fatalf("expected default max depth %d to survive, got %d", base.MaxDepth, got.MaxDepth)
	}
}

func TestValidatedCloneWithOverridesRejectsInvalidCombinations(t *testing.T) {
	adapter := &mcpOptionsAdapter{options: opts.NewOptions()}
	base := adapter.options.GetConfig()
	config.ApplyDefaults(&base)
	adapter.options.SetConfig(base)

	if _, err := adapter.validatedCloneWithOverrides(mcpOverrides{Exclude: "apps/*"}); err == nil {
		t.Fatal("expected exclude without recursive to fail validation")
	}
	if _, err := adapter.validatedCloneWithOverrides(mcpOverrides{Recursive: true, Image: "alpine:latest"}); err == nil {
		t.Fatal("expected recursive with image to fail validation")
	}
	if _, err := adapter.validatedCloneWithOverrides(mcpOverrides{Recursive: true, MaxDepth: 4}); err != nil {
		t.Fatalf("expected valid recursive overrides to pass, got %v", err)
	}
}
