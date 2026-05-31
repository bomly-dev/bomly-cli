package opts

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

type FlagGroup string

const (
	FlagGroupTarget                  FlagGroup = "target"
	FlagGroupAnalysis                FlagGroup = "analysis"
	FlagGroupSelectors               FlagGroup = "selectors"
	FlagGroupExecution               FlagGroup = "execution"
	FlagGroupExperimentalRemediation FlagGroup = "experimental-remediation"
)

func bindFlagOptions(cmd *cobra.Command, cfg *config.Resolved) error {
	flags := cmd.PersistentFlags()
	flags.StringVar(&cfg.Config, "config", "", "YAML config file path")
	flags.BoolVarP(&cfg.Quiet, "quiet", "q", false, "Suppress non-error stderr output")
	flags.CountVarP(&cfg.Verbosity, "verbose", "v", "Increase verbosity (-v = info, -vv = debug)")

	return nil
}

func BindCommandFlagGroups(cmd *cobra.Command, cfg *config.Resolved, groups ...FlagGroup) error {
	if cmd == nil || cfg == nil {
		return nil
	}

	seen := make(map[FlagGroup]struct{}, len(groups))
	for _, group := range groups {
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		switch group {
		case FlagGroupTarget:
			bindTargetFlags(cmd.Flags(), cfg)
		case FlagGroupAnalysis:
			bindAnalysisFlags(cmd.Flags(), cfg)
		case FlagGroupSelectors:
			bindSelectorFlags(cmd.Flags(), cfg)
			if err := bindSelectorCompletionFlags(cmd); err != nil {
				return err
			}
		case FlagGroupExecution:
			bindExecutionFlags(cmd.Flags(), cfg)
		case FlagGroupExperimentalRemediation:
			bindExperimentalRemediationFlags(cmd.Flags(), cfg)
		}
	}

	return nil
}

func bindTargetFlags(flags *pflag.FlagSet, cfg *config.Resolved) {
	flags.StringVar(&cfg.Path, "path", "", "Execution target path")
	flags.StringVar(&cfg.Container, "container", "", "Container image reference to scan with Syft")
	flags.StringVar(&cfg.URL, "url", "", "Git repository URL to clone and scan")
	flags.StringVar(&cfg.Ref, "ref", "", "Git reference to scan when using --url")
	flags.BoolVar(&cfg.SBOM, "sbom", false, "Treat the selected filesystem target as an SBOM file")
}

func bindAnalysisFlags(flags *pflag.FlagSet, cfg *config.Resolved) {
	flags.BoolVar(&cfg.Enrich, "enrich", false, "Enrich packages with external license and vulnerability data")
	flags.BoolVar(&cfg.Audit, "audit", false, "Evaluate policy and create findings from package vulnerability data")
	flags.BoolVar(&cfg.Reachability, "reachability", false, "[Experimental] Run code analysis to confirm whether vulnerabilities are reachable from application code")
	flags.StringArrayVar(&cfg.FailOn, "fail-on", nil, "Constraint(s) for which findings should be created. Repeatable; constraints AND together. Severity: any|low|medium|high|critical. Reachability: reachable. Exploitability: exploitable. Example: --fail-on low --fail-on reachable")
	flags.StringArrayVar(&cfg.FailOnScopes, "fail-on-scope", nil, "Dependency scope that may produce failing findings: runtime, development, or unknown. Repeatable")
	flags.StringArrayVar(&cfg.AllowVulnerabilityIDs, "allow-vulnerability-id", nil, "Vulnerability ID to ignore during policy evaluation. Repeatable")
	flags.StringArrayVar(&cfg.AllowLicenses, "allow-license", nil, "Allowed SPDX license identifier or expression. Repeatable")
	flags.StringArrayVar(&cfg.DenyLicenses, "deny-license", nil, "Denied SPDX license identifier or expression. Repeatable")
	flags.StringArrayVar(&cfg.LicenseExemptPackages, "license-exempt-package", nil, "Package URL exempt from license policy checks. Repeatable")
	flags.StringArrayVar(&cfg.DenyPackages, "deny-package", nil, "Package URL to deny. Repeatable")
	flags.StringArrayVar(&cfg.DenyGroups, "deny-group", nil, "Package URL namespace to deny. Repeatable")
	flags.StringArrayVar(&cfg.ProtectedPackages, "protected-package", nil, "Canonical package name to protect from typosquatting. Repeatable")
	flags.StringVar(&cfg.TyposquatThreshold, "typosquat-threshold", "", "Similarity threshold for typosquatting detection")
	flags.StringVar(&cfg.TyposquatMode, "typosquat-mode", "", "Typosquatting policy mode: warn or fail")
	flags.BoolVar(&cfg.WarnOnly, "warn-only", false, "Downgrade failing findings to warnings")
}

func bindSelectorFlags(flags *pflag.FlagSet, cfg *config.Resolved) {
	flags.StringVar(&cfg.Analyzers, "analyzers", "", "Reachability analyzer selectors. Use names. Prefix with '+' to append defaults or '-' to remove from defaults")
	flags.StringVar(&cfg.Ecosystems, "ecosystems", "", "Ecosystems to use; supports +name/-name to add/remove from all")
	flags.StringVar(&cfg.Detectors, "detectors", "", "Detector selectors. Use names or aliases. Prefix with '+' to append defaults or '-' to remove from defaults")
	flags.StringVar(&cfg.Auditors, "auditors", "", "Auditor selectors. Use names or aliases. Prefix with '+' to append defaults or '-' to remove from defaults")
	flags.StringVar(&cfg.Matchers, "matchers", "", "Matcher selectors. Use names or aliases. Prefix with '+' to append defaults or '-' to remove from defaults")
}

func bindExecutionFlags(flags *pflag.FlagSet, cfg *config.Resolved) {
	flags.StringVarP(&cfg.Format, "format", "f", "", "Output format: text, json, markdown, sarif")
	BindJSONFormatFlag(flags, &cfg.Format, "Shortcut for --format json")
	flags.StringArrayVarP(&cfg.Outputs, "output", "o", nil, "Additional output target as <format> or <format>=<path>; repeat for multiple outputs")
	flags.BoolVar(&cfg.Interactive, "interactive", false, "Open an interactive terminal UI")
	flags.BoolVar(&cfg.InstallFirst, "install-first", false, "Run detector-specific dependency installation before resolving graphs")
	flags.StringArrayVar(&cfg.InstallArgs, "install-arg", nil, "Additional detector-specific install argument; may be repeated")
}

func bindExperimentalRemediationFlags(flags *pflag.FlagSet, cfg *config.Resolved) {
	flags.BoolVar(&cfg.ExperimentalRemediate, "experimental-remediate", false, "[Experimental] Propose local-only dependency upgrade paths in the interactive vulnerabilities pane (requires --interactive and --enrich)")
}

// BindJSONFormatFlag binds --json as a no-argument shortcut for setting format to json.
func BindJSONFormatFlag(flags *pflag.FlagSet, format *string, usage string) {
	if flags == nil {
		return
	}
	flags.BoolFunc("json", usage, func(value string) error {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("parse json flag: %w", err)
		}
		if enabled && format != nil {
			*format = "json"
		}
		return nil
	})
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
	if flagChanged(cmd, "experimental-remediate") {
		dst.ExperimentalRemediate = flags.ExperimentalRemediate
	}
	if flagChanged(cmd, "fail-on") {
		dst.FailOn = append([]string(nil), flags.FailOn...)
	}
	if flagChanged(cmd, "fail-on-scope") {
		dst.FailOnScopes = append([]string(nil), flags.FailOnScopes...)
	}
	if flagChanged(cmd, "allow-vulnerability-id") {
		dst.AllowVulnerabilityIDs = append([]string(nil), flags.AllowVulnerabilityIDs...)
	}
	if flagChanged(cmd, "allow-license") {
		dst.AllowLicenses = append([]string(nil), flags.AllowLicenses...)
	}
	if flagChanged(cmd, "deny-license") {
		dst.DenyLicenses = append([]string(nil), flags.DenyLicenses...)
	}
	if flagChanged(cmd, "license-exempt-package") {
		dst.LicenseExemptPackages = append([]string(nil), flags.LicenseExemptPackages...)
	}
	if flagChanged(cmd, "deny-package") {
		dst.DenyPackages = append([]string(nil), flags.DenyPackages...)
	}
	if flagChanged(cmd, "deny-group") {
		dst.DenyGroups = append([]string(nil), flags.DenyGroups...)
	}
	if flagChanged(cmd, "protected-package") {
		dst.ProtectedPackages = append([]string(nil), flags.ProtectedPackages...)
	}
	if flagChanged(cmd, "typosquat-threshold") {
		dst.TyposquatThreshold = flags.TyposquatThreshold
	}
	if flagChanged(cmd, "typosquat-mode") {
		dst.TyposquatMode = flags.TyposquatMode
	}
	if flagChanged(cmd, "warn-only") {
		dst.WarnOnly = flags.WarnOnly
	}
	if flagChanged(cmd, "analyzers") {
		dst.Analyzers = flags.Analyzers
	}
	if flagChanged(cmd, "format") || (flagChanged(cmd, "json") && strings.EqualFold(flags.Format, "json")) {
		dst.Format = flags.Format
	}
	if flagChanged(cmd, "output") {
		dst.Outputs = append([]string(nil), flags.Outputs...)
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

func bindSelectorCompletionFlags(cmd *cobra.Command) error {
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
