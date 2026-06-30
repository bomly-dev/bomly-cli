package cli

import (
	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/spf13/cobra"
)

// rootHelpTemplate defines the help text for the root command
const rootHelpTemplate = `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}Usage:{{if .Runnable}}
  {{.UseLine}}{{else if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{exitCodesHelpSection .}}{{optionValuesHelpSection .}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

func optionValuesHelpSection(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}

	flags := cmd.Flags()
	if flags.Lookup("ecosystems") == nil &&
		flags.Lookup("detectors") == nil {
		return ""
	}

	return "\n\nExplore available detectors, matchers, and auditors with `bomly plugins list`."
}

func exitCodesHelpSection(cmd *cobra.Command) string {
	if cmd == nil || cmd.Parent() != nil {
		return ""
	}

	return "\n\nExit Codes:\n  0 success\n  1 execution error\n  2 policy violation\n  3 resolution failure\n  4 invalid input"
}

// startupLogoHelpFunc wraps Cobra's default help function so the Bomly logo
// animation plays before rendering help output.
func startupLogoHelpFunc(root *cobra.Command) func(*cobra.Command, []string) {
	defaultHelp := root.HelpFunc()
	return func(cmd *cobra.Command, args []string) {
		render.StartupLogo(cmd.ErrOrStderr())
		defaultHelp(cmd, args)
	}
}
