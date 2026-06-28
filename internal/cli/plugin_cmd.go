package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/config"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/internal/registry"
	plugschema "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newPluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage Bomly managed plugins",
		Example: "  bomly plugin list --all\n" +
			"  bomly plugin info osv",
	}
	cmd.AddCommand(
		newPluginListCmd(),
		newPluginInfoCmd(),
		newPluginInstallCmd(),
		newPluginUninstallCmd(),
		newPluginEnableCmd(),
		newPluginDisableCmd(),
		newPluginVerifyCmd(),
		newPluginTestCmd(),
		newPluginDoctorCmd(),
	)
	return cmd
}

func newPluginListCmd() *cobra.Command {
	var includeBuiltIn bool
	var includeExternal bool
	var enabledOnly bool
	var disabledOnly bool
	var showAll bool
	var includeDetectors bool
	var includeMatchers bool
	var includeAuditors bool
	var includeAnalyzers bool
	var format string
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List built-in and installed plugins",
		Example: "  bomly plugin list --detectors\n  bomly plugin list --external --json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			selectedFormat, err := parsePluginListFormat(format)
			if err != nil {
				return err
			}
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			builtins := builtInPluginInfos(current, cmd.Root().Version)
			all, err := managedplugin.ListPluginInfos("", builtins)
			if err != nil {
				return err
			}
			kindFilter := pluginKindFilter{
				detectors: includeDetectors,
				matchers:  includeMatchers,
				auditors:  includeAuditors,
				analyzers: includeAnalyzers,
			}
			filtered := make([]managedplugin.Info, 0, len(all))
			for _, info := range all {
				if !kindFilter.includes(info.Kind) {
					continue
				}
				if includeBuiltIn && !info.BuiltIn {
					continue
				}
				if includeExternal && info.BuiltIn {
					continue
				}
				if !showAll && enabledOnly && !info.Enabled {
					continue
				}
				if !showAll && disabledOnly && info.Enabled {
					continue
				}
				filtered = append(filtered, info)
			}
			if selectedFormat == pluginListFormatJSON {
				return writeJSON(streams.reportWriter(), managedplugin.GroupPluginInfos(filtered))
			}
			if len(filtered) == 0 {
				_, err := fmt.Fprintln(streams.reportWriter(), "No plugins matched the selected filters.")
				return err
			}
			sortPluginInfos(filtered)
			_, err = io.WriteString(streams.reportWriter(), renderPluginListTables(filtered, kindFilter))
			return err
		},
	}
	cmd.Flags().BoolVar(&showAll, "all", false, "Show all plugins, including disabled ones")
	cmd.Flags().BoolVar(&includeBuiltIn, "builtin", false, "Show built-in plugins only")
	cmd.Flags().BoolVar(&includeExternal, "external", false, "Show external plugins only")
	cmd.Flags().BoolVar(&enabledOnly, "enabled", false, "Show enabled plugins only")
	cmd.Flags().BoolVar(&disabledOnly, "disabled", false, "Show disabled plugins only")
	cmd.Flags().BoolVar(&includeDetectors, "detectors", false, "Show detector plugins")
	cmd.Flags().BoolVar(&includeMatchers, "matchers", false, "Show matcher plugins")
	cmd.Flags().BoolVar(&includeAuditors, "auditors", false, "Show auditor plugins")
	cmd.Flags().BoolVar(&includeAnalyzers, "analyzers", false, "Show reachability analyzer plugins")
	cmd.Flags().StringVar(&format, "format", pluginListFormatTable, "Render output format: table or json")
	opts.BindJSONFormatFlag(cmd.Flags(), &format, "Shortcut for --format json")
	return cmd
}

const (
	pluginListFormatTable = "table"
	pluginListFormatJSON  = "json"
)

type pluginKindFilter struct {
	detectors bool
	matchers  bool
	auditors  bool
	analyzers bool
}

func (f pluginKindFilter) hasSelections() bool {
	return f.detectors || f.matchers || f.auditors || f.analyzers
}

func (f pluginKindFilter) includes(kind plugschema.PluginKind) bool {
	if !f.hasSelections() {
		return true
	}
	switch kind {
	case plugschema.PluginKindDetector:
		return f.detectors
	case plugschema.PluginKindMatcher:
		return f.matchers
	case plugschema.PluginKindAuditor:
		return f.auditors
	case plugschema.PluginKindAnalyzer:
		return f.analyzers
	default:
		return false
	}
}

func parsePluginListFormat(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		normalized = pluginListFormatTable
	}
	switch normalized {
	case pluginListFormatTable, pluginListFormatJSON:
		return normalized, nil
	default:
		return "", exit.InvalidInputError("parse format: unsupported format %q", value)
	}
}

func newPluginInfoCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:     "info <id>",
		Short:   "Show plugin metadata",
		Example: "  bomly plugin info osv\n  bomly plugin info npm-native --json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			all, err := managedplugin.ListPluginInfos("", builtInPluginInfos(current, cmd.Root().Version))
			if err != nil {
				return err
			}
			id := strings.TrimSpace(args[0])
			for _, info := range all {
				if info.ID != id {
					continue
				}
				if jsonOutput {
					return writeJSON(streams.reportWriter(), info)
				}
				return renderPluginInfo(streams.reportWriter(), info)
			}
			return exit.InvalidInputError("plugin %q not found", id)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Render plugin metadata as JSON")
	return cmd
}

func newPluginInstallCmd() *cobra.Command {
	var devBinary bool
	var checksum string
	var insecureSkipChecksum bool
	cmd := &cobra.Command{
		Use:   "install <source>",
		Short: "Install a managed plugin from an archive, URL, or dev binary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			result, err := managedplugin.Install(options.PluginLaunchContext(cmd.Context()), "", args[0], managedplugin.InstallOptions{
				DevBinary:            devBinary,
				Checksum:             checksum,
				InsecureSkipChecksum: insecureSkipChecksum,
			})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(
				streams.reportWriter(),
				"Installed %s@%s\nKind: %s\nRuntime: %s\nSource: %s\nChecksum: %s\n",
				result.Manifest.ID,
				result.Manifest.Version,
				result.Manifest.Kind,
				result.Manifest.Runtime,
				nonEmptyString(result.ResolvedSource, args[0]),
				nonEmptyString(result.Installed.Checksum, "not recorded"),
			)
			if err != nil {
				return err
			}
			if devBinary {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
					"Warning: installed in development mode — no checksum was recorded. Only enable plugins you built or fully trust.\n")
			}
			if insecureSkipChecksum {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
					"Warning: checksum verification was skipped. Verify this plugin's integrity before enabling it.\n")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&devBinary, "dev", false, "Install a local development plugin binary instead of an archive")
	cmd.Flags().StringVar(&checksum, "checksum", "", "Expected SHA256 checksum for the plugin archive")
	cmd.Flags().BoolVar(&insecureSkipChecksum, "insecure-skip-checksum", false, "Allow URL installs without checksum verification")
	return cmd
}

func newPluginUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall <id>",
		Short: "Uninstall an external plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			if err := managedplugin.Uninstall("", strings.TrimSpace(args[0])); err != nil {
				return err
			}
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			_, err = fmt.Fprintf(streams.reportWriter(), "uninstalled %s\n", strings.TrimSpace(args[0]))
			return err
		},
	}
}

func newPluginEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable <id>",
		Short: "Enable an installed external plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			pluginRecord, err := managedplugin.Enable("", strings.TrimSpace(args[0]))
			if err != nil {
				return err
			}
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			if _, err := fmt.Fprintf(streams.reportWriter(), "enabled %s@%s\n", pluginRecord.ID, pluginRecord.Version); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"Warning: %s@%s will run as a native subprocess with full OS execution privileges during scans. Only enable plugins from sources you trust.\n",
				pluginRecord.ID, pluginRecord.Version)
			return nil
		},
	}
}

func newPluginDisableCmd() *cobra.Command {
	return togglePluginStateCmd("disable", "Disable an installed external plugin", managedplugin.Disable, "disabled")
}

func togglePluginStateCmd(
	use string,
	short string,
	fn func(string, string) (*managedplugin.InstalledPlugin, error),
	label string,
) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			pluginRecord, err := fn("", strings.TrimSpace(args[0]))
			if err != nil {
				return err
			}
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			_, err = fmt.Fprintf(streams.reportWriter(), "%s %s@%s\n", label, pluginRecord.ID, pluginRecord.Version)
			return err
		},
	}
}

func newPluginVerifyCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "verify <id>",
		Short: "Verify an installed plugin manifest, binary, checksum, and runtime descriptor",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			result, err := managedplugin.Verify(options.PluginLaunchContext(cmd.Context()), "", strings.TrimSpace(args[0]))
			if err != nil {
				return err
			}
			if result.Installed != nil && result.Installed.Checksum == "" {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
					"Warning: no checksum is recorded for %s@%s — this plugin was installed without integrity verification. Treat it as untrusted.\n",
					result.ID, result.Version)
			}
			if jsonOutput {
				return writeJSON(streams.reportWriter(), result)
			}
			if _, err := fmt.Fprintf(streams.reportWriter(), "Verified %s@%s\n", result.ID, result.Version); err != nil {
				return err
			}
			for _, check := range result.Checks {
				if _, err := fmt.Fprintf(streams.reportWriter(), "[ok] %s\n", check); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Render verification results as JSON")
	return cmd
}

func newPluginTestCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "test <id>",
		Short: "Test runtime readiness for an installed plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			builtins := builtInPluginInfos(current, cmd.Root().Version)
			all, _ := managedplugin.ListPluginInfos("", builtins)
			result, err := managedplugin.Test(options.PluginLaunchContext(cmd.Context()), "", strings.TrimSpace(args[0]), all)
			if err != nil {
				return pluginCommandError(err)
			}
			if jsonOutput {
				if err := writeJSON(streams.reportWriter(), result); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(streams.reportWriter(), "Tested %s@%s\n", result.ID, result.Version); err != nil {
					return err
				}
				status := "not ready"
				label := "[fail]"
				if result.Ready {
					status = "ready"
					label = "[ok]"
				}
				if _, err := fmt.Fprintf(streams.reportWriter(), "%s %s: %s\n", label, nonEmptyString(result.Probe, "runtime readiness"), status); err != nil {
					return err
				}
			}
			if !result.Ready {
				return fmt.Errorf("plugin %s is not ready", result.ID)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Render runtime test results as JSON")
	return cmd
}

func newPluginDoctorCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "doctor <id>",
		Short: "Run verify and runtime readiness checks for an installed plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			builtins := builtInPluginInfos(current, cmd.Root().Version)
			all, _ := managedplugin.ListPluginInfos("", builtins)
			result, err := managedplugin.Doctor(options.PluginLaunchContext(cmd.Context()), "", strings.TrimSpace(args[0]), all)
			if err != nil {
				return pluginCommandError(err)
			}
			if jsonOutput {
				if err := writeJSON(streams.reportWriter(), result); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(streams.reportWriter(), "Doctor report for %s@%s\n", result.ID, result.Version); err != nil {
					return err
				}
				for _, check := range result.Checks {
					if _, err := fmt.Fprintf(streams.reportWriter(), "[ok] %s\n", check); err != nil {
						return err
					}
				}
				status := "not ready"
				label := "[fail]"
				if result.Ready {
					status = "ready"
					label = "[ok]"
				}
				if _, err := fmt.Fprintf(streams.reportWriter(), "%s %s: %s\n", label, nonEmptyString(result.Probe, "runtime readiness"), status); err != nil {
					return err
				}
			}
			if !result.Healthy {
				return fmt.Errorf("plugin %s is unhealthy", result.ID)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Render doctor results as JSON")
	return cmd
}

func pluginCommandError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "is not installed") {
		return exit.InvalidInputError("%v", err)
	}
	if strings.Contains(err.Error(), "does not support runtime readiness probes") {
		return exit.InvalidInputError("%v", err)
	}
	return err
}

func builtInPluginInfos(current config.Resolved, coreVersion string) []managedplugin.Info {
	infos := make([]managedplugin.Info, 0)
	reg := registry.NewRegistry(opts.RegistryConfigsFromResolved(current), *zap.NewNop())
	reg.Build()

	// Build name → instance maps for ReadyFn population.
	detectorInstances := collectDetectorInstances(reg.AllDetectors())
	matcherInstances := make(map[string]plugschema.Matcher)
	for _, m := range reg.AllMatchers() {
		matcherInstances[m.Descriptor().Name] = m
	}
	auditorInstances := make(map[string]plugschema.Auditor)
	for _, a := range reg.AllAuditors() {
		auditorInstances[a.Descriptor().Name] = a
	}
	analyzerInstances := make(map[string]plugschema.Analyzer)
	for _, a := range reg.AllAnalyzers() {
		analyzerInstances[a.Descriptor().Name] = a
	}

	detectorByName := make(map[string]plugschema.DetectorDescriptor)
	registeredNames := make(map[string]struct{})
	for _, descriptor := range reg.DetectorDescriptors() {
		d := descriptor
		detectorByName[d.Name] = d
		registeredNames[d.Name] = struct{}{}
		info := detectorPluginInfo(&d, coreVersion, reg.DefaultEnabledDetectorNames(), string(reg.DetectorOrigin(d.Name)))
		if det, ok := detectorInstances[d.Name]; ok {
			det := det
			info.ReadyFn = func(ctx context.Context) (bool, string, error) {
				return det.Ready(ctx, plugschema.DetectionRequest{}) == nil, "detector-ready", nil
			}
		}
		infos = append(infos, info)
	}

	seenFallbackTraversal := make(map[string]struct{})
	for _, detector := range reg.Detectors(plugschema.DetectionRequest{}) {
		collectFallbackDetectorDescriptors(detector, detectorByName, seenFallbackTraversal)
	}

	additionalNames := make([]string, 0)
	for name := range detectorByName {
		if _, ok := registeredNames[name]; ok {
			continue
		}
		additionalNames = append(additionalNames, name)
	}
	sort.Strings(additionalNames)
	for _, name := range additionalNames {
		d := detectorByName[name]
		info := detectorPluginInfo(&d, coreVersion, reg.DefaultEnabledDetectorNames(), string(reg.DetectorOrigin(d.Name)))
		if det, ok := detectorInstances[d.Name]; ok {
			det := det
			info.ReadyFn = func(ctx context.Context) (bool, string, error) {
				return det.Ready(ctx, plugschema.DetectionRequest{}) == nil, "detector-ready", nil
			}
		}
		infos = append(infos, info)
	}

	for _, descriptor := range reg.MatcherDescriptors() {
		d := descriptor
		info := matcherPluginInfo(&d, coreVersion, reg.DefaultEnabledMatcherNames())
		if m, ok := matcherInstances[d.Name]; ok {
			m := m
			info.ReadyFn = func(ctx context.Context) (bool, string, error) {
				return m.Ready(ctx, plugschema.MatchRequest{}) == nil, "matcher-ready", nil
			}
		}
		infos = append(infos, info)
	}
	for _, descriptor := range reg.AuditorDescriptors() {
		d := descriptor
		info := auditorPluginInfo(&d, coreVersion, reg.DefaultEnabledAuditorNames())
		if a, ok := auditorInstances[d.Name]; ok {
			a := a
			info.ReadyFn = func(ctx context.Context) (bool, string, error) {
				return a.Ready(ctx, plugschema.AuditRequest{}) == nil, "auditor-ready", nil
			}
		}
		infos = append(infos, info)
	}
	for _, descriptor := range reg.AnalyzerDescriptors() {
		d := descriptor
		info := analyzerPluginInfo(&d, coreVersion, reg.DefaultEnabledAnalyzerNames())
		if a, ok := analyzerInstances[d.Name]; ok {
			a := a
			info.ReadyFn = func(ctx context.Context) (bool, string, error) {
				return a.Ready(ctx, plugschema.AnalyzeRequest{}) == nil, "analyzer-ready", nil
			}
		}
		infos = append(infos, info)
	}
	return infos
}

// collectDetectorInstances builds a flat name→instance map that includes fallback
// detectors reachable from the provided primary detectors.
func collectDetectorInstances(primaries []plugschema.Detector) map[string]plugschema.Detector {
	out := make(map[string]plugschema.Detector)
	var walk func(d plugschema.Detector)
	walk = func(d plugschema.Detector) {
		if d == nil {
			return
		}
		name := strings.TrimSpace(d.Descriptor().Name)
		if name != "" {
			if _, ok := out[name]; !ok {
				out[name] = d
			}
		}
		if fb, ok := d.(plugschema.FallbackDetector); ok {
			walk(fb.FallbackDetector())
		}
	}
	for _, p := range primaries {
		walk(p)
	}
	return out
}

func collectFallbackDetectorDescriptors(
	detector plugschema.Detector,
	detectorByName map[string]plugschema.DetectorDescriptor,
	seen map[string]struct{},
) {
	if detector == nil {
		return
	}
	name := strings.TrimSpace(detector.Descriptor().Name)
	if name != "" {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
	}
	provider, ok := detector.(plugschema.FallbackDetector)
	if !ok {
		return
	}
	fallback := provider.FallbackDetector()
	if fallback == nil {
		return
	}
	fallbackDescriptor := fallback.Descriptor()
	fallbackName := strings.TrimSpace(fallbackDescriptor.Name)
	if fallbackName != "" {
		if _, ok := detectorByName[fallbackName]; !ok {
			detectorByName[fallbackName] = fallbackDescriptor
		}
	}
	collectFallbackDetectorDescriptors(fallback, detectorByName, seen)
}

func detectorPluginInfo(descriptor *plugschema.DetectorDescriptor, coreVersion string, defaultEnabled []string, sourceType string) managedplugin.Info {
	return managedplugin.Info{
		Manifest: managedplugin.Manifest{
			SchemaVersion:    plugschema.PackageManifestSchemaVersion,
			ID:               descriptor.Name,
			Name:             descriptor.Name,
			Version:          nonEmptyString(coreVersion, "unknown"),
			Kind:             plugschema.PluginKindDetector,
			Runtime:          "builtin",
			PluginAPIVersion: plugschema.PluginAPIVersion,
		},
		DetectorDescriptor: cloneDetectorDescriptor(descriptor),
		BuiltIn:            true,
		Enabled:            slices.Contains(defaultEnabled, descriptor.Name),
		SourceType:         sourceType,
	}
}

func matcherPluginInfo(descriptor *plugschema.MatcherDescriptor, coreVersion string, defaultEnabled []string) managedplugin.Info {
	return managedplugin.Info{
		Manifest: managedplugin.Manifest{
			SchemaVersion:    plugschema.PackageManifestSchemaVersion,
			ID:               descriptor.Name,
			Name:             descriptor.Name,
			Version:          nonEmptyString(coreVersion, "unknown"),
			Kind:             plugschema.PluginKindMatcher,
			Runtime:          "builtin",
			PluginAPIVersion: plugschema.PluginAPIVersion,
		},
		MatcherDescriptor: cloneMatcherDescriptor(descriptor),
		BuiltIn:           true,
		Enabled:           slices.Contains(defaultEnabled, descriptor.Name),
		SourceType:        "builtin",
	}
}

func auditorPluginInfo(descriptor *plugschema.AuditorDescriptor, coreVersion string, defaultEnabled []string) managedplugin.Info {
	return managedplugin.Info{
		Manifest: managedplugin.Manifest{
			SchemaVersion:    plugschema.PackageManifestSchemaVersion,
			ID:               descriptor.Name,
			Name:             descriptor.Name,
			Version:          nonEmptyString(coreVersion, "unknown"),
			Kind:             plugschema.PluginKindAuditor,
			Runtime:          "builtin",
			PluginAPIVersion: plugschema.PluginAPIVersion,
		},
		AuditorDescriptor: cloneAuditorDescriptor(descriptor),
		BuiltIn:           true,
		Enabled:           slices.Contains(defaultEnabled, descriptor.Name),
		SourceType:        "builtin",
	}
}

func analyzerPluginInfo(descriptor *plugschema.AnalyzerDescriptor, coreVersion string, defaultEnabled []string) managedplugin.Info {
	return managedplugin.Info{
		Manifest: managedplugin.Manifest{
			SchemaVersion:    plugschema.PackageManifestSchemaVersion,
			ID:               descriptor.Name,
			Name:             descriptor.Name,
			Version:          nonEmptyString(coreVersion, "unknown"),
			Kind:             plugschema.PluginKindAnalyzer,
			Runtime:          "builtin",
			PluginAPIVersion: plugschema.PluginAPIVersion,
		},
		AnalyzerDescriptor: cloneAnalyzerDescriptor(descriptor),
		BuiltIn:            true,
		Enabled:            slices.Contains(defaultEnabled, descriptor.Name),
		SourceType:         "builtin",
	}
}

func cloneDetectorDescriptor(descriptor *plugschema.DetectorDescriptor) *plugschema.DetectorDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	copyValue.PackageManagerSupport = completeDetectorPackageManagerSupport(descriptor.SupportedManagers, descriptor.PackageManagerSupport)
	copyValue.Tags = append([]string(nil), descriptor.Tags...)
	copyValue.FallbackDetectors = append([]string(nil), descriptor.FallbackDetectors...)
	return &copyValue
}

func completeDetectorPackageManagerSupport(
	managers []plugschema.PackageManager,
	src []plugschema.PackageManagerSupport,
) []plugschema.PackageManagerSupport {
	out := clonePackageManagerSupport(src)
	for idx, entry := range out {
		if len(entry.EvidencePatterns) == 0 {
			out[idx].EvidencePatterns = registry.EvidencePatternsForPackageManager(entry.PackageManager)
		}
	}
	for _, manager := range managers {
		if containsPackageManagerSupport(out, manager) {
			continue
		}
		out = append(out, plugschema.Support(manager, registry.EvidencePatternsForPackageManager(manager)...))
	}
	return out
}

func clonePackageManagerSupport(src []plugschema.PackageManagerSupport) []plugschema.PackageManagerSupport {
	out := make([]plugschema.PackageManagerSupport, len(src))
	for i, entry := range src {
		out[i] = entry
		out[i].EvidencePatterns = append([]string(nil), entry.EvidencePatterns...)
	}
	return out
}

func containsPackageManagerSupport(values []plugschema.PackageManagerSupport, manager plugschema.PackageManager) bool {
	for _, value := range values {
		if value.PackageManager == manager {
			return true
		}
	}
	return false
}

func cloneMatcherDescriptor(descriptor *plugschema.MatcherDescriptor) *plugschema.MatcherDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	copyValue.Aliases = append([]string(nil), descriptor.Aliases...)
	copyValue.Tags = append([]string(nil), descriptor.Tags...)
	return &copyValue
}

func cloneAuditorDescriptor(descriptor *plugschema.AuditorDescriptor) *plugschema.AuditorDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	return &copyValue
}

func cloneAnalyzerDescriptor(descriptor *plugschema.AnalyzerDescriptor) *plugschema.AnalyzerDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	copyValue.SupportedLanguages = append([]plugschema.Language(nil), descriptor.SupportedLanguages...)
	copyValue.SupportedTiers = append([]plugschema.ReachabilityTier(nil), descriptor.SupportedTiers...)
	return &copyValue
}

func writeJSON(w io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

func renderPluginInfo(w io.Writer, info managedplugin.Info) error {
	lines := [][2]string{
		{"ID", info.ID},
		{"Name", nonEmptyString(info.Name, info.ID)},
		{"Kind", string(info.Kind)},
		{"Source", pluginSourceValue(info)},
		{"State", pluginStateValue(info)},
		{"Version", info.Version},
		{"Runtime", info.Runtime},
	}
	if displayName := pluginInfoDisplayName(info); displayName != "" {
		lines = append(lines, [2]string{"Display Name", displayName})
	}
	if aliases := pluginInfoAliases(info); len(aliases) > 0 {
		lines = append(lines, [2]string{"Aliases", strings.Join(aliases, ", ")})
	}
	if ecosystems := pluginInfoEcosystems(info); len(ecosystems) > 0 {
		lines = append(lines, [2]string{"Ecosystems", joinEcosystems(ecosystems)})
	}
	if managers := pluginInfoPackageManagers(info); len(managers) > 0 {
		lines = append(lines, [2]string{"Package Managers", joinPackageManagers(managers)})
	}
	if languages := pluginInfoLanguages(info); len(languages) > 0 {
		lines = append(lines, [2]string{"Languages", joinLanguages(languages)})
	}
	if tags := pluginInfoTags(info); len(tags) > 0 {
		lines = append(lines, [2]string{"Tags", strings.Join(tags, ", ")})
	}
	if info.Description != "" {
		lines = append(lines, [2]string{"Description", info.Description})
	}
	if info.Homepage != "" {
		lines = append(lines, [2]string{"Homepage", info.Homepage})
	}
	if info.Installed != nil {
		lines = append(lines,
			[2]string{"Install Path", info.Installed.Path},
			[2]string{"Recorded Checksum", nonEmptyString(info.Installed.Checksum, "not recorded")},
		)
	}
	labelWidth := 0
	for _, line := range lines {
		if width := len(render.StripANSI(line[0])); width > labelWidth {
			labelWidth = width
		}
	}
	for _, line := range lines {
		if _, err := fmt.Fprintf(w, "%-*s : %s\n", labelWidth, line[0], line[1]); err != nil {
			return err
		}
	}
	return nil
}

func pluginInfoEcosystems(info managedplugin.Info) []plugschema.Ecosystem {
	switch info.Kind {
	case plugschema.PluginKindDetector:
		if info.DetectorDescriptor != nil {
			return append([]plugschema.Ecosystem(nil), info.DetectorDescriptor.SupportedEcosystems...)
		}
	case plugschema.PluginKindMatcher:
		if info.MatcherDescriptor != nil {
			return append([]plugschema.Ecosystem(nil), info.MatcherDescriptor.SupportedEcosystems...)
		}
	case plugschema.PluginKindAuditor:
		if info.AuditorDescriptor != nil {
			return append([]plugschema.Ecosystem(nil), info.AuditorDescriptor.SupportedEcosystems...)
		}
	case plugschema.PluginKindAnalyzer:
		if info.AnalyzerDescriptor != nil {
			return append([]plugschema.Ecosystem(nil), info.AnalyzerDescriptor.SupportedEcosystems...)
		}
	}
	return nil
}

func pluginInfoPackageManagers(info managedplugin.Info) []plugschema.PackageManager {
	switch info.Kind {
	case plugschema.PluginKindDetector:
		if info.DetectorDescriptor != nil {
			return append([]plugschema.PackageManager(nil), info.DetectorDescriptor.SupportedManagers...)
		}
	case plugschema.PluginKindMatcher:
		if info.MatcherDescriptor != nil {
			return append([]plugschema.PackageManager(nil), info.MatcherDescriptor.SupportedManagers...)
		}
	case plugschema.PluginKindAuditor:
		if info.AuditorDescriptor != nil {
			return append([]plugschema.PackageManager(nil), info.AuditorDescriptor.SupportedManagers...)
		}
	case plugschema.PluginKindAnalyzer:
		if info.AnalyzerDescriptor != nil {
			return append([]plugschema.PackageManager(nil), info.AnalyzerDescriptor.SupportedManagers...)
		}
	}
	return nil
}

// pluginInfoLanguages returns the SupportedLanguages list for plugin
// kinds that carry one. Today only Analyzer plugins do; other kinds
// return nil so `bomly plugin info` cleanly omits the Languages line.
func pluginInfoLanguages(info managedplugin.Info) []plugschema.Language {
	if info.Kind == plugschema.PluginKindAnalyzer && info.AnalyzerDescriptor != nil {
		return append([]plugschema.Language(nil), info.AnalyzerDescriptor.SupportedLanguages...)
	}
	return nil
}

func pluginInfoTags(info managedplugin.Info) []string {
	switch info.Kind {
	case plugschema.PluginKindDetector:
		if info.DetectorDescriptor != nil {
			return append([]string(nil), info.DetectorDescriptor.Tags...)
		}
	case plugschema.PluginKindMatcher:
		if info.MatcherDescriptor != nil {
			return append([]string(nil), info.MatcherDescriptor.Tags...)
		}
	case plugschema.PluginKindAuditor:
		if info.AuditorDescriptor != nil {
			return append([]string(nil), info.AuditorDescriptor.Tags...)
		}
	case plugschema.PluginKindAnalyzer:
		if info.AnalyzerDescriptor != nil {
			return append([]string(nil), info.AnalyzerDescriptor.Tags...)
		}
	}
	return nil
}

func pluginInfoDisplayName(info managedplugin.Info) string {
	switch info.Kind {
	case plugschema.PluginKindDetector:
		if info.DetectorDescriptor != nil {
			return strings.TrimSpace(info.DetectorDescriptor.DisplayName)
		}
	case plugschema.PluginKindMatcher:
		if info.MatcherDescriptor != nil {
			return strings.TrimSpace(info.MatcherDescriptor.DisplayName)
		}
	case plugschema.PluginKindAuditor:
		if info.AuditorDescriptor != nil {
			return strings.TrimSpace(info.AuditorDescriptor.DisplayName)
		}
	case plugschema.PluginKindAnalyzer:
		if info.AnalyzerDescriptor != nil {
			return strings.TrimSpace(info.AnalyzerDescriptor.DisplayName)
		}
	}
	return ""
}

func pluginInfoAliases(info managedplugin.Info) []string {
	switch info.Kind {
	case plugschema.PluginKindDetector:
		if info.DetectorDescriptor != nil {
			return cleanStrings(info.DetectorDescriptor.Aliases)
		}
	case plugschema.PluginKindMatcher:
		if info.MatcherDescriptor != nil {
			return cleanStrings(info.MatcherDescriptor.Aliases)
		}
	case plugschema.PluginKindAuditor:
		if info.AuditorDescriptor != nil {
			return cleanStrings(info.AuditorDescriptor.Aliases)
		}
	case plugschema.PluginKindAnalyzer:
		if info.AnalyzerDescriptor != nil {
			return cleanStrings(info.AnalyzerDescriptor.Aliases)
		}
	}
	return nil
}

func sortPluginInfos(items []managedplugin.Info) {
	sort.Slice(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		if left.Enabled != right.Enabled {
			return left.Enabled && !right.Enabled
		}
		leftEcosystem := pluginSortEcosystem(left)
		rightEcosystem := pluginSortEcosystem(right)
		if leftEcosystem != rightEcosystem {
			if leftEcosystem == "" {
				return false
			}
			if rightEcosystem == "" {
				return true
			}
			return leftEcosystem < rightEcosystem
		}
		return left.ID < right.ID
	})
}

func pluginSortEcosystem(info managedplugin.Info) string {
	if info.Kind != plugschema.PluginKindDetector || info.DetectorDescriptor == nil {
		return ""
	}
	items := make([]string, 0, len(info.DetectorDescriptor.SupportedEcosystems))
	for _, ecosystem := range info.DetectorDescriptor.SupportedEcosystems {
		value := strings.TrimSpace(string(ecosystem))
		if value != "" {
			items = append(items, value)
		}
	}
	if len(items) == 0 {
		return ""
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func joinEcosystems(values []plugschema.Ecosystem) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, string(value))
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func joinPackageManagers(values []plugschema.PackageManager) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, value.Name())
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func joinLanguages(values []plugschema.Language) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.TrimSpace(string(value))
		if v == "" {
			continue
		}
		items = append(items, v)
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func renderPluginListTables(items []managedplugin.Info, kindFilter pluginKindFilter) string {
	detectors := make([]managedplugin.Info, 0)
	matchers := make([]managedplugin.Info, 0)
	auditors := make([]managedplugin.Info, 0)
	analyzers := make([]managedplugin.Info, 0)
	for _, info := range items {
		switch info.Kind {
		case plugschema.PluginKindDetector:
			detectors = append(detectors, info)
		case plugschema.PluginKindMatcher:
			matchers = append(matchers, info)
		case plugschema.PluginKindAuditor:
			auditors = append(auditors, info)
		case plugschema.PluginKindAnalyzer:
			analyzers = append(analyzers, info)
		}
	}

	var b strings.Builder
	appendTable := func(title string, headers []string, rows [][]string) {
		if len(rows) == 0 {
			return
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(title)
		b.WriteString(":\n")
		b.WriteString(renderPluginListTable(headers, rows))
	}

	if kindFilter.includes(plugschema.PluginKindDetector) {
		appendTable("Detectors", []string{"ECOSYSTEMS", "PACKAGE MANAGERS", "NAME", "TYPE", "STATE"}, detectorPluginRows(detectors))
	}
	if kindFilter.includes(plugschema.PluginKindMatcher) {
		appendTable("Matchers", []string{"NAME", "TYPE", "STATE"}, basicPluginRows(matchers))
	}
	if kindFilter.includes(plugschema.PluginKindAuditor) {
		appendTable("Auditors", []string{"NAME", "TYPE", "STATE"}, basicPluginRows(auditors))
	}
	if kindFilter.includes(plugschema.PluginKindAnalyzer) {
		appendTable("Analyzers", []string{"LANGUAGES", "ECOSYSTEMS", "PACKAGE MANAGERS", "NAME", "TYPE", "STATE"}, analyzerPluginRows(analyzers))
	}
	if b.Len() > 0 {
		b.WriteString("\n* Complete plugin metadata is available with --json.\n")
	}

	return b.String()
}

func detectorPluginRows(items []managedplugin.Info) [][]string {
	rows := make([][]string, 0, len(items))
	for _, info := range items {
		rows = append(rows, []string{
			nonEmptyString(summarizePluginListValue(pluginDetectorEcosystems(info), 6), "-"),
			nonEmptyString(summarizePluginListValue(pluginDetectorPackageManagers(info), 6), "-"),
			pluginListName(info),
			colorPluginType(pluginTypeValue(info), info),
			colorPluginState(pluginStateValue(info)),
		})
	}
	return rows
}

func basicPluginRows(items []managedplugin.Info) [][]string {
	rows := make([][]string, 0, len(items))
	for _, info := range items {
		rows = append(rows, []string{
			pluginListName(info),
			colorPluginType(pluginTypeValue(info), info),
			colorPluginState(pluginStateValue(info)),
		})
	}
	return rows
}

func analyzerPluginRows(items []managedplugin.Info) [][]string {
	rows := make([][]string, 0, len(items))
	for _, info := range items {
		rows = append(rows, []string{
			nonEmptyString(summarizePluginListValue(pluginAnalyzerLanguages(info), 6), "-"),
			nonEmptyString(summarizePluginListValue(pluginAnalyzerEcosystems(info), 6), "-"),
			nonEmptyString(summarizePluginListValue(pluginAnalyzerPackageManagers(info), 6), "-"),
			pluginListName(info),
			colorPluginType(pluginTypeValue(info), info),
			colorPluginState(pluginStateValue(info)),
		})
	}
	return rows
}

func renderPluginListTable(headers []string, rows [][]string) string {
	maxWidths := pluginListTableMaxWidths(headers)
	widths := make([]int, len(headers))
	for idx, header := range headers {
		widths[idx] = len(header)
	}
	for _, row := range rows {
		for idx, value := range row {
			if width := len(render.StripANSI(value)); width > widths[idx] {
				widths[idx] = width
			}
		}
	}
	for idx, maxWidth := range maxWidths {
		if maxWidth > 0 && widths[idx] > maxWidth {
			widths[idx] = maxWidth
		}
	}
	var b strings.Builder
	border := func(left, fill, join, right string) string {
		var line strings.Builder
		line.WriteString(left)
		for idx, width := range widths {
			line.WriteString(strings.Repeat(fill, width+2))
			if idx < len(widths)-1 {
				line.WriteString(join)
			}
		}
		line.WriteString(right)
		return line.String()
	}
	writeRow := func(values []string, header bool) {
		cells := make([][]string, len(values))
		height := 1
		for idx, value := range values {
			lines := []string{value}
			if !header {
				lines = wrapPluginListTableCell(value, widths[idx])
			}
			if len(lines) > height {
				height = len(lines)
			}
			cells[idx] = lines
		}
		for lineIdx := 0; lineIdx < height; lineIdx++ {
			b.WriteString("│")
			for idx, lines := range cells {
				cell := ""
				if lineIdx < len(lines) {
					cell = lines[lineIdx]
				}
				if header {
					cell = render.Style(cell, render.Bold)
				}
				padding := widths[idx] - len(render.StripANSI(cell))
				b.WriteString(" ")
				b.WriteString(cell)
				b.WriteString(strings.Repeat(" ", padding+1))
				b.WriteString("│")
			}
			b.WriteString("\n")
		}
	}
	b.WriteString(border("┌", "─", "┬", "┐"))
	b.WriteString("\n")
	writeRow(headers, true)
	b.WriteString(border("├", "─", "┼", "┤"))
	b.WriteString("\n")
	for _, row := range rows {
		writeRow(row, false)
	}
	b.WriteString(border("└", "─", "┴", "┘"))
	b.WriteString("\n")
	return b.String()
}

func pluginListTableMaxWidths(headers []string) []int {
	widths := make([]int, len(headers))
	for idx, header := range headers {
		switch header {
		case "NAME":
			widths[idx] = 48
		case "PACKAGE MANAGERS":
			widths[idx] = 28
		case "ECOSYSTEMS":
			widths[idx] = 28
		case "LANGUAGES":
			widths[idx] = 28
		default:
			widths[idx] = 0
		}
	}
	return widths
}

func wrapPluginListTableCell(value string, width int) []string {
	if len(render.StripANSI(value)) <= width {
		return []string{value}
	}
	return render.WrapLines(render.WrapTextLines(value, width), width)
}

func pluginListName(info managedplugin.Info) string {
	if displayName := pluginInfoDisplayName(info); displayName != "" {
		return fmt.Sprintf("%s (%s)", displayName, info.ID)
	}
	return nonEmptyString(info.Name, info.ID)
}

func summarizePluginListValue(value string, maxItems int) string {
	if maxItems < 1 {
		maxItems = 1
	}
	parts := strings.Split(value, ", ")
	if len(parts) <= maxItems {
		return value
	}
	return strings.Join(parts[:maxItems], ", ") + fmt.Sprintf(", +%d more*", len(parts)-maxItems)
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func pluginTypeValue(info managedplugin.Info) string {
	return pluginSourceValue(info)
}

func pluginSourceValue(info managedplugin.Info) string {
	if strings.TrimSpace(info.SourceType) != "" {
		return info.SourceType
	}
	if info.BuiltIn {
		return "builtin"
	}
	return "external"
}

func pluginStateValue(info managedplugin.Info) string {
	if info.Enabled {
		return "enabled"
	}
	return "disabled"
}

func colorPluginState(state string) string {
	switch state {
	case "enabled":
		return render.Style(state, render.Green)
	case "disabled":
		return render.Style(state, render.Yellow, render.Dim)
	default:
		return state
	}
}

func colorPluginType(value string, info managedplugin.Info) string {
	if !info.BuiltIn {
		return render.Style(value, render.Yellow, render.Dim)
	}
	return value
}

func pluginDetectorPackageManagers(info managedplugin.Info) string {
	if info.DetectorDescriptor == nil {
		return ""
	}
	items := make([]string, 0, len(info.DetectorDescriptor.PackageManagerSupport))
	for _, support := range info.DetectorDescriptor.PackageManagerSupport {
		name := strings.TrimSpace(support.PackageManager.Name())
		if name == "" {
			continue
		}
		if !containsPluginValue(items, name) {
			items = append(items, name)
		}
	}
	if len(items) == 0 {
		for _, manager := range info.DetectorDescriptor.SupportedManagers {
			name := strings.TrimSpace(manager.Name())
			if name == "" {
				continue
			}
			if !containsPluginValue(items, name) {
				items = append(items, name)
			}
		}
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func pluginAnalyzerLanguages(info managedplugin.Info) string {
	if info.AnalyzerDescriptor == nil {
		return ""
	}
	items := make([]string, 0, len(info.AnalyzerDescriptor.SupportedLanguages))
	for _, language := range info.AnalyzerDescriptor.SupportedLanguages {
		name := strings.TrimSpace(string(language))
		if name == "" {
			continue
		}
		if !containsPluginValue(items, name) {
			items = append(items, name)
		}
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func pluginAnalyzerEcosystems(info managedplugin.Info) string {
	if info.AnalyzerDescriptor == nil {
		return ""
	}
	items := make([]string, 0, len(info.AnalyzerDescriptor.SupportedEcosystems))
	for _, ecosystem := range info.AnalyzerDescriptor.SupportedEcosystems {
		name := strings.TrimSpace(string(ecosystem))
		if name == "" {
			continue
		}
		if !containsPluginValue(items, name) {
			items = append(items, name)
		}
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func pluginAnalyzerPackageManagers(info managedplugin.Info) string {
	if info.AnalyzerDescriptor == nil {
		return ""
	}
	items := make([]string, 0, len(info.AnalyzerDescriptor.SupportedManagers))
	for _, manager := range info.AnalyzerDescriptor.SupportedManagers {
		name := strings.TrimSpace(manager.Name())
		if name == "" {
			continue
		}
		if !containsPluginValue(items, name) {
			items = append(items, name)
		}
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func pluginDetectorEcosystems(info managedplugin.Info) string {
	if info.DetectorDescriptor == nil {
		return ""
	}
	items := make([]string, 0, len(info.DetectorDescriptor.SupportedEcosystems))
	for _, ecosystem := range info.DetectorDescriptor.SupportedEcosystems {
		name := strings.TrimSpace(string(ecosystem))
		if name == "" {
			continue
		}
		if !containsPluginValue(items, name) {
			items = append(items, name)
		}
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func containsPluginValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func nonEmptyString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
