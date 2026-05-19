package opts

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/config"
)

func TestApplyFlagOverridesOnlyUsesChangedFlags(t *testing.T) {
	options := &Options{}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupExecution); err != nil {
		t.Fatalf("BindCommandFlagGroups() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--format", "json", "--output", "markdown=summary.md", "--install-arg", "legacy-peer-deps"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}

	dst := config.Resolved{
		Format:      "text",
		Ecosystems:  "go",
		InstallArgs: []string{"old"},
	}
	applyFlagOverrides(&dst, options.ResolvedConfig, root)

	if dst.Format != "json" {
		t.Fatalf("expected changed format flag to override, got %q", dst.Format)
	}
	if len(dst.Outputs) != 1 || dst.Outputs[0] != "markdown=summary.md" {
		t.Fatalf("expected changed output flag to override, got %#v", dst.Outputs)
	}
	if dst.Ecosystems != "go" {
		t.Fatalf("expected unchanged ecosystems to remain, got %q", dst.Ecosystems)
	}
	if len(dst.InstallArgs) != 1 || dst.InstallArgs[0] != "legacy-peer-deps" {
		t.Fatalf("expected changed install args to override, got %#v", dst.InstallArgs)
	}
}
