package cli

import (
	"context"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

// init registers custom template functions for use in Cobra help and version text templates.
func init() {
	cobra.AddTemplateFunc("optionValuesHelpSection", optionValuesHelpSection)
	cobra.AddTemplateFunc("exitCodesHelpSection", exitCodesHelpSection)
	cobra.AddTemplateFunc("versionDetails", versionDetailsTemplateValue)
}

// Execute runs the bomly CLI.
func Execute(version string) error {
	root, err := newRootCmd(version)
	if err != nil {
		return err
	}
	return normalizeExecuteError(root.Execute())
}

// normalizeExecuteError checks if the error from executing the root
// command is related to missing required flags and, if so, wraps it
// in a more user-friendly error message. Otherwise, it returns the original error.
func normalizeExecuteError(err error) error {
	if err != nil && strings.Contains(err.Error(), "required flag(s)") {
		return exit.InvalidInputError("%v", err)
	}
	return err
}

// newRootCmd creates the root Cobra command for the bomly CLI, setting up global options, subcommands, and templates.
func newRootCmd(version string) (*cobra.Command, error) {
	options := opts.NewOptions()
	root := &cobra.Command{
		Use:                   "bomly [command]",
		Short:                 "A modern CLI for SBOM generation, dependency analysis, and software supply chain intelligence.",
		Example:               "  bomly scan --interactive\n  bomly diff --base main --head HEAD --json\n  bomly explain pkg:npm/react",
		Version:               version,
		SilenceUsage:          true,
		SilenceErrors:         true,
		DisableFlagsInUseLine: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "benchmark" {
				return nil
			}
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			if err := options.ResolveConfig(cmd); err != nil {
				return err
			}
			cmd.SetContext(options.PluginLaunchContext(opts.ToContext(cmd.Context(), options)))
			logResolvedOptions(cmd)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if rootHasCommandRequiredFlags(cmd) {
				return exit.InvalidInputError("a command is required when using flags")
			}
			return cmd.Help()
		},
	}

	if err := options.Bind(root); err != nil {
		return nil, err
	}
	root.SetContext(opts.ToContext(context.Background(), options))

	root.SetVersionTemplate(rootVersionTemplate)
	root.SetHelpTemplate(rootHelpTemplate)

	explainCmd := newExplainCmd()
	if err := opts.BindCommandFlagGroups(explainCmd, &options.ResolvedConfig,
		opts.FlagGroupTarget,
		opts.FlagGroupAnalysis,
		opts.FlagGroupSelectors,
		opts.FlagGroupExecution,
	); err != nil {
		return nil, err
	}

	scanCmd := newScanCmd()
	if err := opts.BindCommandFlagGroups(scanCmd, &options.ResolvedConfig,
		opts.FlagGroupTarget,
		opts.FlagGroupAnalysis,
		opts.FlagGroupSelectors,
		opts.FlagGroupExecution,
	); err != nil {
		return nil, err
	}

	diffCmd := newDiffCmd()
	if err := opts.BindCommandFlagGroups(diffCmd, &options.ResolvedConfig,
		opts.FlagGroupTarget,
		opts.FlagGroupAnalysis,
		opts.FlagGroupSelectors,
		opts.FlagGroupExecution,
	); err != nil {
		return nil, err
	}

	pluginCmd := newPluginCmd()
	sbomCmd := newSBOMCmd()
	mcpCmd := newMcpCmd()
	versionCmd := newVersionCmd(version)
	benchmarkCmd := newBenchmarkCmd()

	root.AddCommand(explainCmd)
	root.AddCommand(scanCmd)
	root.AddCommand(diffCmd)
	root.AddCommand(pluginCmd)
	root.AddCommand(sbomCmd)
	root.AddCommand(mcpCmd)
	root.AddCommand(versionCmd)
	root.AddCommand(benchmarkCmd)

	setHelpFuncRecursive(root, startupLogoHelpFunc(root))

	return root, nil
}

func setHelpFuncRecursive(cmd *cobra.Command, helpFn func(*cobra.Command, []string)) {
	if cmd == nil || helpFn == nil {
		return
	}
	cmd.SetHelpFunc(helpFn)
	for _, child := range cmd.Commands() {
		setHelpFuncRecursive(child, helpFn)
	}
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

func logResolvedOptions(cmd *cobra.Command) {
	if cmd == nil {
		return
	}
	logger := commandLogger(cmd, "startup")
	options, err := commandOptions(cmd)
	if err != nil {
		return
	}
	resolved := options.GetConfig()
	logger.Debug("Resolved options",
		zap.String("path", resolved.Path),
		zap.String("container", resolved.Container),
		zap.String("url", resolved.URL),
		zap.String("ref", resolved.Ref),
		zap.Bool("sbom", resolved.SBOM),
		zap.Bool("enrich", resolved.Enrich),
		zap.Bool("audit", resolved.Audit),
		zap.Strings("fail_on", resolved.FailOn),
		zap.Bool("analyze", resolved.Analyze),
		zap.String("analyzers", resolved.Analyzers),
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
