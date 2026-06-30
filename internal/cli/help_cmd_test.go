package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestOptionValuesHelpSection(t *testing.T) {
	if got := optionValuesHelpSection(nil); got != "" {
		t.Fatalf("expected empty section for nil command, got %q", got)
	}

	cmd := &cobra.Command{Use: "test"}
	if got := optionValuesHelpSection(cmd); got != "" {
		t.Fatalf("expected empty section without selector flags, got %q", got)
	}

	cmd.Flags().String("ecosystems", "", "")
	got := optionValuesHelpSection(cmd)
	if !strings.Contains(got, "bomly plugins list") {
		t.Fatalf("expected plugin list hint, got %q", got)
	}
}

func TestExitCodesHelpSection(t *testing.T) {
	if got := exitCodesHelpSection(nil); got != "" {
		t.Fatalf("expected empty section for nil command, got %q", got)
	}

	root := &cobra.Command{Use: "bomly"}
	got := exitCodesHelpSection(root)
	if !strings.Contains(got, "Exit Codes:") {
		t.Fatalf("expected exit code section, got %q", got)
	}
	if !strings.Contains(got, "4 invalid input") {
		t.Fatalf("expected invalid input description, got %q", got)
	}

	child := &cobra.Command{Use: "scan"}
	root.AddCommand(child)
	if got := exitCodesHelpSection(child); got != "" {
		t.Fatalf("expected empty section for subcommand, got %q", got)
	}
}
