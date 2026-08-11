package cli

import (
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/support"
	"github.com/spf13/cobra"
)

// newInternalCmd groups hidden maintenance commands that support this
// repository's docs tooling but are not part of the public CLI surface.
func newInternalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "internal",
		Short:  "Internal maintenance commands",
		Hidden: true,
	}
	cmd.AddCommand(newDocsGenCmd())
	return cmd
}

// newDocsGenCmd regenerates every generated documentation artifact (config
// reference, JSON schemas, schema markdown, support matrix, component docs)
// into the given output directory. `make generate` runs this through the
// built binary so the committed docs/ tree always reflects the binary's
// actual configuration and output surface.
func newDocsGenCmd() *cobra.Command {
	outputDir := "docs"
	cmd := &cobra.Command{
		Use:    "docs-gen",
		Short:  "Regenerate generated documentation artifacts",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			lines, err := support.GenerateDocs(outputDir)
			if err != nil {
				return fmt.Errorf("generate documentation: %w", err)
			}
			out := cmd.OutOrStdout()
			for _, line := range lines {
				_, _ = fmt.Fprintln(out, line)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&outputDir, "output", "docs", "Directory the generated documentation artifacts are written to")
	return cmd
}
