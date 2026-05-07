package cli

import (
	"bytes"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/spf13/cobra"
)

func TestCommandLoggerWritesOnlyWhenVerbose(t *testing.T) {
	var stderr bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetErr(&stderr)
	cmd.SetContext(opts.ToContext(cmd.Context(), &opts.Options{ResolvedConfig: config.Resolved{Verbosity: 1}}))

	commandLogger(cmd, "test").Info("hello")
	if stderr.Len() == 0 {
		t.Fatal("expected verbose logger to write to command stderr")
	}
}

func TestCommandLoggerSuppressesDefaultAndQuietOutput(t *testing.T) {
	for name, cfg := range map[string]config.Resolved{
		"default": {},
		"quiet":   {Quiet: true, Verbosity: 2},
	} {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			cmd := &cobra.Command{Use: "test"}
			cmd.SetErr(&stderr)
			cmd.SetContext(opts.ToContext(cmd.Context(), &opts.Options{ResolvedConfig: cfg}))

			commandLogger(cmd, "test").Info("hidden")
			if stderr.Len() != 0 {
				t.Fatalf("expected no log output, got %q", stderr.String())
			}
		})
	}
}
