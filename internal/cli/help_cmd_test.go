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
	if !strings.Contains(got, "bomly plugin list") {
		t.Fatalf("expected plugin list hint, got %q", got)
	}
}
