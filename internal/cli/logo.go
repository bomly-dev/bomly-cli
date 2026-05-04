package cli

import (
	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/spf13/cobra"
)

// startupLogoHelpFunc wraps the root command's help function so that running
// `bomly help` plays the Bomly logo animation before printing help text.
func startupLogoHelpFunc(root *cobra.Command) func(*cobra.Command, []string) {
	defaultHelp := root.HelpFunc()
	return func(cmd *cobra.Command, args []string) {
		if cmd == root {
			render.StartupLogo(cmd.ErrOrStderr())
		}
		defaultHelp(cmd, args)
	}
}
