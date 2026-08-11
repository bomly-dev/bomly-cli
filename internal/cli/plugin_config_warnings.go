package cli

import (
	"encoding/json"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/config"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	plugschema "github.com/bomly-dev/bomly-sdk"
	"github.com/spf13/cobra"
)

// warnPluginConfigIssues emits warning-only diagnostics for the resolved
// `plugins:` configuration: deprecated legacy flat blocks, blocks naming
// unknown components, and blocks rejected by a plugin's advertised config
// schema. Warnings go to stderr so machine-readable stdout stays clean.
func warnPluginConfigIssues(cmd *cobra.Command, options *opts.Options) {
	if cmd == nil || options == nil {
		return
	}
	current := options.GetConfig()
	if current.Plugins.IsEmpty() {
		return
	}
	catalog := pluginConfigCatalog(current, cmd.Root().Version)
	for _, warning := range config.ValidatePluginConfigs(current, catalog) {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Warning: "+warning)
	}
}

// pluginConfigCatalog builds the known-component universe (built-ins plus
// installed managed plugins, with aliases) and their advertised config
// schemas for plugins-config validation.
func pluginConfigCatalog(current config.Resolved, coreVersion string) config.PluginCatalog {
	catalog := config.PluginCatalog{
		Components: map[string][]string{
			config.PluginKindDetector: {},
			config.PluginKindMatcher:  {},
			config.PluginKindAuditor:  {},
			config.PluginKindAnalyzer: {},
		},
		Schemas: map[string]json.RawMessage{},
	}
	infos, err := managedplugin.ListPluginInfos("", builtInPluginInfos(current, coreVersion))
	if err != nil {
		// Warning-only machinery must never fail command startup; without a
		// component universe, skip the unknown-component checks entirely.
		return config.PluginCatalog{}
	}
	for _, info := range infos {
		kind := pluginConfigKind(info.Kind)
		if kind == "" {
			continue
		}
		names := append([]string{info.ID}, pluginInfoAliases(info)...)
		catalog.Components[kind] = append(catalog.Components[kind], names...)
		if schema := pluginInfoConfigSchema(info); len(schema) > 0 {
			catalog.Schemas[config.SchemaKey(kind, info.ID)] = schema
		}
	}
	return catalog
}

func pluginConfigKind(kind plugschema.PluginKind) string {
	switch kind {
	case plugschema.PluginKindDetector:
		return config.PluginKindDetector
	case plugschema.PluginKindMatcher:
		return config.PluginKindMatcher
	case plugschema.PluginKindAuditor:
		return config.PluginKindAuditor
	case plugschema.PluginKindAnalyzer:
		return config.PluginKindAnalyzer
	default:
		return ""
	}
}

// pluginInfoConfigSchema returns the component's advertised config schema, if
// any, across the four descriptor kinds.
func pluginInfoConfigSchema(info managedplugin.Info) json.RawMessage {
	switch info.Kind {
	case plugschema.PluginKindDetector:
		if info.DetectorDescriptor != nil {
			return info.DetectorDescriptor.ConfigSchema
		}
	case plugschema.PluginKindMatcher:
		if info.MatcherDescriptor != nil {
			return info.MatcherDescriptor.ConfigSchema
		}
	case plugschema.PluginKindAuditor:
		if info.AuditorDescriptor != nil {
			return info.AuditorDescriptor.ConfigSchema
		}
	case plugschema.PluginKindAnalyzer:
		if info.AnalyzerDescriptor != nil {
			return info.AnalyzerDescriptor.ConfigSchema
		}
	}
	return nil
}
