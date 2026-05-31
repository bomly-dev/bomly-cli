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

func TestApplyFlagOverridesJSONShortcut(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		startValue string
		want       string
	}{
		{
			name:       "json shortcut overrides existing format",
			args:       []string{"--json"},
			startValue: "markdown",
			want:       "json",
		},
		{
			name:       "json false does not override existing format",
			args:       []string{"--json=false"},
			startValue: "markdown",
			want:       "markdown",
		},
		{
			name:       "format wins when it appears after json",
			args:       []string{"--json", "--format", "markdown"},
			startValue: "text",
			want:       "markdown",
		},
		{
			name:       "json wins when it appears after format",
			args:       []string{"--format", "markdown", "--json"},
			startValue: "text",
			want:       "json",
		},
		{
			name:       "json false leaves preceding format override intact",
			args:       []string{"--format", "markdown", "--json=false"},
			startValue: "text",
			want:       "markdown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			options := &Options{}
			root := newTestRootCommand(t)
			if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupExecution); err != nil {
				t.Fatalf("BindCommandFlagGroups() error = %v", err)
			}
			if err := root.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags() error = %v", err)
			}

			dst := config.Resolved{Format: tc.startValue}
			applyFlagOverrides(&dst, options.ResolvedConfig, root)

			if dst.Format != tc.want {
				t.Fatalf("expected format %q, got %q", tc.want, dst.Format)
			}
		})
	}
}

func TestApplyFlagOverridesExperimentalRemediate(t *testing.T) {
	options := &Options{}
	root := newTestRootCommand(t)
	if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupExperimentalRemediation); err != nil {
		t.Fatalf("BindCommandFlagGroups() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--experimental-remediate"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}

	var dst config.Resolved
	applyFlagOverrides(&dst, options.ResolvedConfig, root)
	if !dst.ExperimentalRemediate {
		t.Fatal("expected changed --experimental-remediate flag to override config")
	}
}
