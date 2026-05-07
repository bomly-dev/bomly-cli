package cli

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/spf13/cobra"
)

func TestCommandOptionsFindsParentContext(t *testing.T) {
	options := &opts.Options{ResolvedConfig: config.Resolved{Path: "fixture"}}
	parent := &cobra.Command{Use: "parent"}
	child := &cobra.Command{Use: "child"}
	parent.AddCommand(child)
	parent.SetContext(opts.ToContext(parent.Context(), options))

	got, err := commandOptions(child)
	if err != nil {
		t.Fatalf("commandOptions() error = %v", err)
	}
	if got != options {
		t.Fatal("expected options from parent command context")
	}
}

func TestCommandOptionsRequiresInitializedContext(t *testing.T) {
	_, err := commandOptions(&cobra.Command{Use: "test"})
	if err == nil {
		t.Fatal("expected missing options error")
	}
	if !strings.Contains(err.Error(), "command options is not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}
