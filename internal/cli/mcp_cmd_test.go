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

func TestCloneWithOverridesClearsTUIOnlyRemediationGate(t *testing.T) {
	adapter := &mcpOptionsAdapter{options: &opts.Options{
		ResolvedConfig: config.Resolved{
			Interactive:           true,
			ExperimentalRemediate: true,
		},
	}}

	cloned := adapter.cloneWithOverrides(mcpOverrides{})
	if cloned.ResolvedConfig.Interactive || cloned.ResolvedConfig.ExperimentalRemediate {
		t.Fatalf("MCP clone retained TUI-only options: %#v", cloned.ResolvedConfig)
	}
	if resolved := cloned.GetConfig(); resolved.Interactive || resolved.ExperimentalRemediate {
		t.Fatalf("MCP resolved config retained TUI-only options: %#v", resolved)
	}
}
