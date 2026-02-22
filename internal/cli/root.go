package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

// Execute runs the bomly CLI.
func Execute(version string) error {
	root, err := newRootCmd(version)
	if err != nil {
		return err
	}
	return normalizeExecuteError(root.Execute())
}

func normalizeExecuteError(err error) error {
	if err != nil && strings.Contains(err.Error(), "required flag(s)") {
		return invalidInputf("%v", err)
	}
	return err
}

func newRootCmd(version string) (*cobra.Command, error) {
	options := &globalOptions{}

	root := &cobra.Command{
		Use:                   "bomly",
		Short:                 "A CLI for software bill of materials (SBOM) generation and analysis.",
		Version:               version,
		SilenceUsage:          true,
		SilenceErrors:         true,
		DisableFlagsInUseLine: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := options.initialize(cmd); err != nil {
				return err
			}
			logResolvedOptions(cmd, options)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if rootHasCommandRequiredFlags(cmd) {
				return invalidInputf("a command is required when using flags")
			}
			return cmd.Help()
		},
	}
	root.SetHelpTemplate(rootHelpTemplate)
	root.SetVersionTemplate(rootVersionTemplate)
	root.SetHelpFunc(startupLogoHelpFunc(root))
	if err := options.bind(root); err != nil {
		return nil, err
	}

	root.AddCommand(newExplainCmd(options))
	root.AddCommand(newScanCmd(options))
	root.AddCommand(newDiffCmd(options))
	root.AddCommand(newPluginCmd(options))
	root.AddCommand(newVersionCmd(version, options))

	return root, nil
}

func rootHasCommandRequiredFlags(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}

	hasRequiredFlags := false
	cmd.Flags().Visit(func(flag *pflag.Flag) {
		if flag == nil {
			return
		}
		switch flag.Name {
		case "help", "version":
			return
		default:
			hasRequiredFlags = true
		}
	})
	return hasRequiredFlags
}

func logResolvedOptions(cmd *cobra.Command, options *globalOptions) {
	if cmd == nil || options == nil {
		return
	}
	resolved := options.current()
	logger := commandLogger(cmd, options, "startup")
	logger.Debug("Resolved options",
		zap.String("path", resolved.Path),
		zap.String("container", resolved.Container),
		zap.String("url", resolved.URL),
		zap.String("ref", resolved.Ref),
		zap.Bool("sbom", resolved.SBOM),
		zap.Bool("enrich", resolved.Enrich),
		zap.Bool("audit", resolved.Audit),
		zap.String("fail_on", resolved.FailOn),
		zap.String("format", resolved.Format),
		zap.Bool("interactive", resolved.Interactive),
		zap.Bool("quiet", resolved.Quiet),
		zap.String("ecosystems", resolved.Ecosystems),
		zap.String("detectors", resolved.Detectors),
		zap.Bool("install_first", resolved.InstallFirst),
		zap.Strings("install_args", resolved.InstallArgs),
		zap.String("config", resolved.Config),
		zap.Bool("verbose", resolved.Verbosity > 0),
		zap.Int("verbosity", resolved.Verbosity),
		zap.Strings("loaded_files", resolved.LoadedFiles),
	)
}
