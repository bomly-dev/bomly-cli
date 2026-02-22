package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newPlaceholderCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("%s is not implemented yet", cmd.Name())
		},
	}
}
