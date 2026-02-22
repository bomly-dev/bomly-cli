package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/internal/registry"
	plugschema "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newPluginCmd(options *globalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage Bomly managed plugins",
	}
	cmd.AddCommand(
		newPluginListCmd(options),
		newPluginInfoCmd(options),
		newPluginInstallCmd(options),
		newPluginUninstallCmd(options),
		newPluginEnableCmd(options),
		newPluginDisableCmd(options),
		newPluginVerifyCmd(options),
	)
	return cmd
}

func newPluginListCmd(options *globalOptions) *cobra.Command {
	var includeBuiltIn bool
	var includeExternal bool
	var enabledOnly bool
	var disabledOnly bool
	var showAll bool
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List built-in and installed plugins",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			current := options.current()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			builtins := builtInPluginInfos(current, cmd.Root().Version)
			all, err := managedplugin.ListPluginInfos("", builtins)
			if err != nil {
				return err
			}
			filtered := make([]managedplugin.PluginInfo, 0, len(all))
			for _, info := range all {
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
			if jsonOutput {
				return writeJSON(streams.reportWriter(), filtered)
			}
			if len(filtered) == 0 {
				_, err := fmt.Fprintln(streams.reportWriter(), "No plugins matched the selected filters.")
				return err
			}
			sortPluginInfos(filtered)
			_, err = io.WriteString(streams.reportWriter(), renderPluginListTable(filtered))
			return err
		},
	}
	cmd.Flags().BoolVar(&showAll, "all", false, "Show all plugins, including disabled ones")
	cmd.Flags().BoolVar(&includeBuiltIn, "builtin", false, "Show built-in plugins only")
	cmd.Flags().BoolVar(&includeExternal, "external", false, "Show external plugins only")
	cmd.Flags().BoolVar(&enabledOnly, "enabled", false, "Show enabled plugins only")
	cmd.Flags().BoolVar(&disabledOnly, "disabled", false, "Show disabled plugins only")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Render the plugin list as JSON")
	return cmd
}

func newPluginInfoCmd(options *globalOptions) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "info <id>",
		Short: "Show plugin metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			current := options.current()
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
			return invalidInputf("plugin %q not found", id)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Render plugin metadata as JSON")
	return cmd
}

func newPluginInstallCmd(options *globalOptions) *cobra.Command {
	var devBinary bool
	var checksum string
	var insecureSkipChecksum bool
	cmd := &cobra.Command{
		Use:   "install <source>",
		Short: "Install a managed plugin from an archive, URL, or dev binary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			current := options.current()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			result, err := managedplugin.Install(context.Background(), "", args[0], managedplugin.InstallOptions{
				DevBinary:            devBinary,
				Checksum:             checksum,
				InsecureSkipChecksum: insecureSkipChecksum,
			}, options.pluginExecutionPolicy(current))
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
			return err
		},
	}
	cmd.Flags().BoolVar(&devBinary, "dev", false, "Install a local development plugin binary instead of an archive")
	cmd.Flags().StringVar(&checksum, "checksum", "", "Expected SHA256 checksum for the plugin archive")
	cmd.Flags().BoolVar(&insecureSkipChecksum, "insecure-skip-checksum", false, "Allow URL installs without checksum verification")
	return cmd
}

func newPluginUninstallCmd(options *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall <id>",
		Short: "Uninstall an external plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := managedplugin.Uninstall("", strings.TrimSpace(args[0])); err != nil {
				return err
			}
			current := options.current()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			_, err := fmt.Fprintf(streams.reportWriter(), "uninstalled %s\n", strings.TrimSpace(args[0]))
			return err
		},
	}
}

func newPluginEnableCmd(options *globalOptions) *cobra.Command {
	return togglePluginStateCmd(options, "enable", "Enable an installed external plugin", managedplugin.Enable, "enabled")
}

func newPluginDisableCmd(options *globalOptions) *cobra.Command {
	return togglePluginStateCmd(options, "disable", "Disable an installed external plugin", managedplugin.Disable, "disabled")
}

func togglePluginStateCmd(
	options *globalOptions,
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
			pluginRecord, err := fn("", strings.TrimSpace(args[0]))
			if err != nil {
				return err
			}
			current := options.current()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			_, err = fmt.Fprintf(streams.reportWriter(), "%s %s@%s\n", label, pluginRecord.ID, pluginRecord.Version)
			return err
		},
	}
}

func newPluginVerifyCmd(options *globalOptions) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "verify <id>",
		Short: "Verify an installed plugin manifest, binary, checksum, and runtime metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			current := options.current()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			result, err := managedplugin.Verify(context.Background(), "", strings.TrimSpace(args[0]), options.pluginExecutionPolicy(current))
			if err != nil {
				return err
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

func builtInPluginInfos(current resolvedConfig, coreVersion string) []managedplugin.PluginInfo {
	infos := make([]managedplugin.PluginInfo, 0)
	reg := registry.NewRegistry(registryBuilderConfig(current), *zap.NewNop())
	reg.Build()
	for _, descriptor := range reg.DetectorDescriptors() {
		d := descriptor
		metadata := builtInMetadata(d.Name, plugschema.PluginKindDetector)
		infos = append(infos, detectorPluginInfo(metadata, &d, coreVersion, d.Enabled))
	}
	for _, descriptor := range reg.MatcherDescriptors() {
		d := descriptor
		metadata := builtInMetadata(d.Name, plugschema.PluginKindMatcher)
		infos = append(infos, matcherPluginInfo(metadata, &d, coreVersion, d.Enabled))
	}
	for _, descriptor := range reg.AuditorDescriptors() {
		d := descriptor
		metadata := builtInMetadata(d.Name, plugschema.PluginKindAuditor)
		infos = append(infos, auditorPluginInfo(metadata, &d, coreVersion, d.Enabled))
	}
	return infos
}

func builtInMetadata(id string, kind plugschema.PluginKind) *plugschema.PluginMetadata {
	return &plugschema.PluginMetadata{
		ID:               id,
		Name:             id,
		Version:          "builtin",
		Kind:             kind,
		PluginAPIVersion: plugschema.PluginAPIVersion,
	}
}

func detectorPluginInfo(metadata *plugschema.PluginMetadata, descriptor *plugschema.DetectorDescriptor, coreVersion string, enabled bool) managedplugin.PluginInfo {
	return managedplugin.PluginInfo{
		Manifest: managedplugin.Manifest{
			SchemaVersion:      plugschema.PackageManifestSchemaVersion,
			ID:                 metadata.ID,
			Name:               metadata.Name,
			Version:            nonEmptyString(coreVersion, "unknown"),
			Kind:               metadata.Kind,
			Runtime:            "builtin",
			PluginAPIVersion:   plugschema.PluginAPIVersion,
			DetectorDescriptor: cloneDetectorDescriptor(descriptor),
			Description:        metadata.Description,
			Homepage:           metadata.Homepage,
			License:            metadata.License,
		},
		BuiltIn:    true,
		Enabled:    enabled,
		SourceType: string(descriptor.ComponentType),
	}
}

func matcherPluginInfo(metadata *plugschema.PluginMetadata, descriptor *plugschema.MatcherDescriptor, coreVersion string, enabled bool) managedplugin.PluginInfo {
	return managedplugin.PluginInfo{
		Manifest: managedplugin.Manifest{
			SchemaVersion:     plugschema.PackageManifestSchemaVersion,
			ID:                metadata.ID,
			Name:              metadata.Name,
			Version:           nonEmptyString(coreVersion, "unknown"),
			Kind:              metadata.Kind,
			Runtime:           "builtin",
			PluginAPIVersion:  plugschema.PluginAPIVersion,
			MatcherDescriptor: cloneMatcherDescriptor(descriptor),
			Description:       metadata.Description,
			Homepage:          metadata.Homepage,
			License:           metadata.License,
		},
		BuiltIn:    true,
		Enabled:    enabled,
		SourceType: string(descriptor.ComponentType),
	}
}

func auditorPluginInfo(metadata *plugschema.PluginMetadata, descriptor *plugschema.AuditorDescriptor, coreVersion string, enabled bool) managedplugin.PluginInfo {
	return managedplugin.PluginInfo{
		Manifest: managedplugin.Manifest{
			SchemaVersion:     plugschema.PackageManifestSchemaVersion,
			ID:                metadata.ID,
			Name:              metadata.Name,
			Version:           nonEmptyString(coreVersion, "unknown"),
			Kind:              metadata.Kind,
			Runtime:           "builtin",
			PluginAPIVersion:  plugschema.PluginAPIVersion,
			AuditorDescriptor: cloneAuditorDescriptor(descriptor),
			Description:       metadata.Description,
			Homepage:          metadata.Homepage,
			License:           metadata.License,
		},
		BuiltIn:    true,
		Enabled:    enabled,
		SourceType: string(descriptor.ComponentType),
	}
}

func cloneDetectorDescriptor(descriptor *plugschema.DetectorDescriptor) *plugschema.DetectorDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	copyValue.SupportedModes = append([]plugschema.TargetMode(nil), descriptor.SupportedModes...)
	copyValue.PackageManagerSupport = clonePackageManagerSupport(descriptor.PackageManagerSupport)
	copyValue.Capabilities = append([]string(nil), descriptor.Capabilities...)
	copyValue.FallbackDetectors = append([]string(nil), descriptor.FallbackDetectors...)
	return &copyValue
}

func clonePackageManagerSupport(src []plugschema.PackageManagerSupport) []plugschema.PackageManagerSupport {
	out := make([]plugschema.PackageManagerSupport, len(src))
	for i, entry := range src {
		out[i] = entry
		out[i].EvidencePatterns = append([]string(nil), entry.EvidencePatterns...)
	}
	return out
}

func cloneMatcherDescriptor(descriptor *plugschema.MatcherDescriptor) *plugschema.MatcherDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	copyValue.SupportedModes = append([]plugschema.TargetMode(nil), descriptor.SupportedModes...)
	copyValue.Capabilities = append([]string(nil), descriptor.Capabilities...)
	return &copyValue
}

func cloneAuditorDescriptor(descriptor *plugschema.AuditorDescriptor) *plugschema.AuditorDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	copyValue.SupportedModes = append([]plugschema.TargetMode(nil), descriptor.SupportedModes...)
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

func renderPluginInfo(w io.Writer, info managedplugin.PluginInfo) error {
	lines := [][2]string{
		{"ID", info.ID},
		{"Name", nonEmptyString(info.Name, info.ID)},
		{"Kind", string(info.Kind)},
		{"Source", pluginSourceValue(info)},
		{"State", pluginStateValue(info)},
		{"Version", info.Version},
		{"Runtime", info.Runtime},
	}
	if ecosystems := pluginInfoEcosystems(info); len(ecosystems) > 0 {
		lines = append(lines, [2]string{"Ecosystems", joinEcosystems(ecosystems)})
	}
	if managers := pluginInfoPackageManagers(info); len(managers) > 0 {
		lines = append(lines, [2]string{"Package Managers", joinPackageManagers(managers)})
	}
	if features := pluginInfoFeatures(info); len(features) > 0 {
		lines = append(lines, [2]string{"Features", strings.Join(features, ", ")})
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
		if width := len(stripANSI(line[0])); width > labelWidth {
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

func pluginInfoEcosystems(info managedplugin.PluginInfo) []plugschema.Ecosystem {
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
	}
	return nil
}

func pluginInfoPackageManagers(info managedplugin.PluginInfo) []plugschema.PackageManager {
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
	}
	return nil
}

func pluginInfoFeatures(info managedplugin.PluginInfo) []string {
	switch info.Kind {
	case plugschema.PluginKindDetector:
		if info.DetectorDescriptor != nil {
			return append([]string(nil), info.DetectorDescriptor.Capabilities...)
		}
	case plugschema.PluginKindMatcher:
		if info.MatcherDescriptor != nil {
			return append([]string(nil), info.MatcherDescriptor.Capabilities...)
		}
	}
	return nil
}

func sortPluginInfos(items []managedplugin.PluginInfo) {
	sort.Slice(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		if string(left.Kind) != string(right.Kind) {
			return string(left.Kind) < string(right.Kind)
		}
		if pluginSourceValue(left) != pluginSourceValue(right) {
			return pluginSourceValue(left) < pluginSourceValue(right)
		}
		return left.ID < right.ID
	})
}

func joinEcosystems(values []plugschema.Ecosystem) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, string(value))
	}
	return strings.Join(items, ", ")
}

func joinPackageManagers(values []plugschema.PackageManager) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, value.Name())
	}
	return strings.Join(items, ", ")
}

func renderPluginListTable(items []managedplugin.PluginInfo) string {
	headers := []string{"KIND", "SOURCE", "ID", "VERSION", "STATE"}
	rows := make([][]string, 0, len(items))
	for _, info := range items {
		rows = append(rows, []string{
			string(info.Kind),
			pluginSourceValue(info),
			info.ID,
			info.Version,
			colorPluginState(pluginStateValue(info)),
		})
	}
	widths := make([]int, len(headers))
	for idx, header := range headers {
		widths[idx] = len(header)
	}
	for _, row := range rows {
		for idx, value := range row {
			if width := len(stripANSI(value)); width > widths[idx] {
				widths[idx] = width
			}
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
		b.WriteString("│")
		for idx, value := range values {
			cell := value
			if header {
				cell = ansiStyled(value, ansiBold)
			}
			padding := widths[idx] - len(stripANSI(cell))
			b.WriteString(" ")
			b.WriteString(cell)
			b.WriteString(strings.Repeat(" ", padding+1))
			b.WriteString("│")
		}
		b.WriteString("\n")
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

func pluginSourceValue(info managedplugin.PluginInfo) string {
	if strings.TrimSpace(info.SourceType) != "" {
		return info.SourceType
	}
	if info.BuiltIn {
		return "builtin"
	}
	return "external"
}

func pluginStateValue(info managedplugin.PluginInfo) string {
	if info.Enabled {
		return "enabled"
	}
	return "disabled"
}

func colorPluginState(state string) string {
	switch state {
	case "enabled":
		return ansiStyled(state, ansiGreen)
	case "disabled":
		return ansiStyled(state, ansiYellow, ansiDim)
	default:
		return state
	}
}

func nonEmptyString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
