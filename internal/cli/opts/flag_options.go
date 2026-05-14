package opts

import (
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func bindFlagOptions(cmd *cobra.Command, cfg *config.Resolved) error {
	flags := cmd.PersistentFlags()
	flags.StringVar(&cfg.Path, "path", "", "Execution target path")
	flags.StringVar(&cfg.Container, "container", "", "Container image reference to scan with Syft")
	flags.StringVar(&cfg.URL, "url", "", "Git repository URL to clone and scan")
	flags.StringVar(&cfg.Ref, "ref", "", "Git reference to scan when using --url")
	flags.BoolVar(&cfg.SBOM, "sbom", false, "Treat the selected filesystem target as an SBOM file")
	flags.BoolVar(&cfg.Enrich, "enrich", false, "Enrich packages with external license and vulnerability data")
	flags.BoolVar(&cfg.Audit, "audit", false, "Evaluate policy and create findings from package vulnerability data")
	flags.BoolVar(&cfg.Reachability, "reachability", false, "Run code analysis to confirm whether vulnerabilities are reachable from application code")
	flags.StringArrayVar(&cfg.FailOn, "fail-on", nil, "Constraint(s) for which findings should be created. Repeatable; constraints AND together. Severity: any|low|medium|high|critical. Reachability: reachable. Example: --fail-on low --fail-on reachable")
	flags.StringVar(&cfg.Analyzers, "analyzers", "", "Reachability analyzer selectors. Use names. Prefix with '+' to append defaults or '-' to remove from defaults")
	flags.StringVarP(&cfg.Format, "format", "f", "", "Output format: text, json, sarif")
	flags.BoolVar(&cfg.Interactive, "interactive", false, "Open an interactive terminal UI")
	flags.StringVar(&cfg.Ecosystems, "ecosystems", "", "Ecosystems to use; supports +name/-name to add/remove from all")
	flags.StringVar(&cfg.Detectors, "detectors", "", "Detector selectors. Use names or aliases. Prefix with '+' to append defaults or '-' to remove from defaults")
	flags.StringVar(&cfg.Auditors, "auditors", "", "Auditor selectors. Use names or aliases. Prefix with '+' to append defaults or '-' to remove from defaults")
	flags.StringVar(&cfg.Matchers, "matchers", "", "Matcher selectors. Use names or aliases. Prefix with '+' to append defaults or '-' to remove from defaults")
	flags.BoolVar(&cfg.InstallFirst, "install-first", false, "Run detector-specific dependency installation before resolving graphs")
	flags.StringArrayVar(&cfg.InstallArgs, "install-arg", nil, "Additional detector-specific install argument; may be repeated")
	flags.StringVar(&cfg.Config, "config", "", "YAML config file path")
	flags.BoolVarP(&cfg.Quiet, "quiet", "q", false, "Suppress non-error stderr output")
	flags.CountVarP(&cfg.Verbosity, "verbose", "v", "Increase verbosity (-v = info, -vv = debug)")

	return bindDynamicFlagOptions(cmd)
}

func applyFlagOverrides(dst *config.Resolved, flags config.Resolved, cmd *cobra.Command) {
	if dst == nil || cmd == nil {
		return
	}

	if flagChanged(cmd, "path") {
		dst.Path = flags.Path
	}
	if flagChanged(cmd, "container") {
		dst.Container = flags.Container
	}
	if flagChanged(cmd, "url") {
		dst.URL = flags.URL
	}
	if flagChanged(cmd, "ref") {
		dst.Ref = flags.Ref
	}
	if flagChanged(cmd, "sbom") {
		dst.SBOM = flags.SBOM
	}
	if flagChanged(cmd, "enrich") {
		dst.Enrich = flags.Enrich
	}
	if flagChanged(cmd, "audit") {
		dst.Audit = flags.Audit
	}
	if flagChanged(cmd, "reachability") {
		dst.Reachability = flags.Reachability
	}
	if flagChanged(cmd, "fail-on") {
		dst.FailOn = append([]string(nil), flags.FailOn...)
	}
	if flagChanged(cmd, "analyzers") {
		dst.Analyzers = flags.Analyzers
	}
	if flagChanged(cmd, "format") {
		dst.Format = flags.Format
	}
	if flagChanged(cmd, "interactive") {
		dst.Interactive = flags.Interactive
	}
	if flagChanged(cmd, "ecosystems") {
		dst.Ecosystems = flags.Ecosystems
	}
	if flagChanged(cmd, "detectors") {
		dst.Detectors = flags.Detectors
	}
	if flagChanged(cmd, "auditors") {
		dst.Auditors = flags.Auditors
	}
	if flagChanged(cmd, "matchers") {
		dst.Matchers = flags.Matchers
	}
	if flagChanged(cmd, "install-first") {
		dst.InstallFirst = flags.InstallFirst
	}
	if flagChanged(cmd, "install-arg") {
		dst.InstallArgs = append([]string(nil), flags.InstallArgs...)
	}
	if flagChanged(cmd, "config") {
		dst.Config = flags.Config
	}
	if flagChanged(cmd, "quiet") {
		dst.Quiet = flags.Quiet
	}
	if flagChanged(cmd, "verbose") {
		dst.Verbosity = flags.Verbosity
	}
}

func flagChanged(cmd *cobra.Command, name string) bool {
	if flag := cmd.Flags().Lookup(name); flag != nil {
		return flag.Changed
	}
	if flag := cmd.PersistentFlags().Lookup(name); flag != nil {
		return flag.Changed
	}
	if flag := cmd.InheritedFlags().Lookup(name); flag != nil {
		return flag.Changed
	}
	return false
}

func bindDynamicFlagOptions(cmd *cobra.Command) error {
	ecosystems := availableEcosystemOptions()
	detectors := availableDetectorOptions()
	auditors := availableAuditorOptions(zap.NewNop())
	matchers := availableMatcherOptions()
	analyzers := availableAnalyzerOptions()

	if err := cmd.RegisterFlagCompletionFunc("ecosystems", csvCompletionFunc(ecosystems)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("detectors", csvCompletionFunc(detectors)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("auditors", csvCompletionFunc(auditors)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("matchers", csvCompletionFunc(matchers)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("analyzers", csvCompletionFunc(analyzers)); err != nil {
		return err
	}

	return nil
}

func availableEcosystemOptions() []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	for _, descriptor := range reg.DetectorDescriptors() {
		for _, ecosystem := range descriptor.SupportedEcosystems {
			value := strings.TrimSpace(string(ecosystem))
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			options = append(options, value)
		}
	}
	sort.Strings(options)
	return options
}

func availableDetectorOptions() []string {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	rows := buildDetectorOptionRows(reg)
	seen := map[string]struct{}{}
	options := make([]string, 0, len(rows)*2)
	for _, row := range rows {
		if row.Name != "" {
			if _, ok := seen[row.Name]; !ok {
				seen[row.Name] = struct{}{}
				options = append(options, row.Name)
			}
		}
		for _, alias := range row.Aliases {
			if alias == "" {
				continue
			}
			if _, ok := seen[alias]; ok {
				continue
			}
			seen[alias] = struct{}{}
			options = append(options, alias)
		}
	}
	sort.Strings(options)
	return options
}

// availableAuditorOptions returns auditor names for shell completion.
func availableAuditorOptions(logger *zap.Logger) []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *logger)
	reg.Build()
	for _, descriptor := range reg.AuditorDescriptors() {
		name := descriptor.Name
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		options = append(options, name)
	}
	sort.Strings(options)
	return options
}

// availableAnalyzerOptions returns analyzer names for shell completion.
func availableAnalyzerOptions() []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	for _, descriptor := range reg.AnalyzerDescriptors() {
		name := descriptor.Name
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		options = append(options, name)
	}
	sort.Strings(options)
	return options
}

// availableMatcherOptions returns matcher names for shell completion.
func availableMatcherOptions() []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	for _, descriptor := range reg.MatcherDescriptors() {
		name := descriptor.Name
		if name == "" {
			continue
		}
		// Internal names replaced by user-facing aliases below.
		if name == clearlyDefinedCheckerName || name == depsdevCheckerName || name == eolCheckerName {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		options = append(options, name)
	}
	// Emit user-facing aliases only.
	for _, alias := range []string{clearlyDefinedCheckerAlias, depsdevCheckerAlias, eolCheckerAlias} {
		if alias == "" {
			continue
		}
		if _, ok := seen[alias]; ok {
			continue
		}
		seen[alias] = struct{}{}
		options = append(options, alias)
	}
	sort.Strings(options)
	return options
}

func csvCompletionFunc(options []string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		prefix := ""
		current := toComplete
		if idx := strings.LastIndex(toComplete, ","); idx >= 0 {
			prefix = toComplete[:idx+1]
			current = toComplete[idx+1:]
		}

		used := map[string]struct{}{}
		for _, part := range strings.Split(toComplete, ",") {
			value := strings.TrimSpace(part)
			if value == "" {
				continue
			}
			used[strings.TrimLeft(value, "+-")] = struct{}{}
		}

		matches := make([]string, 0, len(options))
		normalizedCurrent := strings.TrimSpace(current)
		sign := ""
		if strings.HasPrefix(normalizedCurrent, "+") || strings.HasPrefix(normalizedCurrent, "-") {
			sign = normalizedCurrent[:1]
			normalizedCurrent = strings.TrimSpace(normalizedCurrent[1:])
		}
		for _, option := range options {
			if _, ok := used[option]; ok && option != normalizedCurrent {
				continue
			}
			if normalizedCurrent != "" && !strings.HasPrefix(option, normalizedCurrent) {
				continue
			}
			matches = append(matches, prefix+sign+option)
		}
		return matches, cobra.ShellCompDirectiveNoFileComp
	}
}
