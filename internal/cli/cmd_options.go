package cli

import (
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/spf13/cobra"
)

func commandOptions(cmd *cobra.Command) (*opts.Options, error) {
	for current := cmd; current != nil; current = current.Parent() {
		if options, ok := opts.FromContext(current.Context()); ok {
			return options, nil
		}
	}
	return nil, fmt.Errorf("command options is not initialized")
}
