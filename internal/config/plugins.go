package config

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Plugin component kind keys used by the kind-scoped plugins configuration.
const (
	PluginKindDetector = "detector"
	PluginKindMatcher  = "matcher"
	PluginKindAuditor  = "auditor"
	PluginKindAnalyzer = "analyzer"
)

// pluginKindBuckets maps the canonical YAML bucket keys to component kinds.
var pluginKindBuckets = []struct {
	YAMLKey string
	Kind    string
}{
	{"detectors", PluginKindDetector},
	{"matchers", PluginKindMatcher},
	{"auditors", PluginKindAuditor},
	{"analyzers", PluginKindAnalyzer},
}

// PluginConfigs is the resolved, kind-scoped plugin configuration.
// Legacy holds deprecated flat `plugins.<id>` blocks, which apply to
// whichever component name matches, regardless of kind.
type PluginConfigs struct {
	Detectors map[string]map[string]any
	Matchers  map[string]map[string]any
	Auditors  map[string]map[string]any
	Analyzers map[string]map[string]any
	Legacy    map[string]map[string]any
}

// IsEmpty reports whether no plugin configuration blocks are present.
func (p PluginConfigs) IsEmpty() bool {
	return len(p.Detectors) == 0 && len(p.Matchers) == 0 && len(p.Auditors) == 0 &&
		len(p.Analyzers) == 0 && len(p.Legacy) == 0
}

// bucketForKind returns the kind-scoped map for a component kind. It accepts
// both singular kind identifiers ("matcher") and the plural YAML bucket keys
// ("matchers").
func (p PluginConfigs) bucketForKind(kind string) map[string]map[string]any {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case PluginKindDetector, "detectors":
		return p.Detectors
	case PluginKindMatcher, "matchers":
		return p.Matchers
	case PluginKindAuditor, "auditors":
		return p.Auditors
	case PluginKindAnalyzer, "analyzers":
		return p.Analyzers
	default:
		return nil
	}
}

// ForComponent returns the configuration block for a (kind, name) pair.
// Kind-scoped blocks win; legacy flat blocks apply to any kind for
// compatibility. Returns nil when no block is configured.
func (p PluginConfigs) ForComponent(kind, name string) map[string]any {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if bucket := p.bucketForKind(kind); bucket != nil {
		if block, ok := bucket[name]; ok {
			return block
		}
	}
	return p.Legacy[name]
}

// ForPlugin returns the configuration block for a component name across all
// kinds. Managed plugin IDs are unique across the install database, so a
// launch-time lookup without the kind is unambiguous in practice.
func (p PluginConfigs) ForPlugin(name string) map[string]any {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	for _, bucket := range pluginKindBuckets {
		if block, ok := p.bucketForKind(bucket.Kind)[name]; ok {
			return block
		}
	}
	return p.Legacy[name]
}

// PluginsFile is the YAML shape of the `plugins:` block. The canonical form
// scopes component blocks by kind:
//
//	plugins:
//	  detectors:  { <name>: {...} }
//	  matchers:   { <name>: {...} }
//	  auditors:   { <name>: {...} }
//	  analyzers:  { <name>: {...} }
//
// The deprecated flat form `plugins.<id>: {...}` keeps working: unknown
// top-level keys are collected into Legacy and reported as deprecated by
// ValidatePluginConfigs.
type PluginsFile struct {
	Detectors map[string]map[string]any `yaml:"detectors,omitempty"`
	Matchers  map[string]map[string]any `yaml:"matchers,omitempty"`
	Auditors  map[string]map[string]any `yaml:"auditors,omitempty"`
	Analyzers map[string]map[string]any `yaml:"analyzers,omitempty"`
	Legacy    map[string]map[string]any `yaml:"-"`
}

// IsEmpty reports whether the file block declares no plugin configuration.
func (f PluginsFile) IsEmpty() bool {
	return len(f.Detectors) == 0 && len(f.Matchers) == 0 && len(f.Auditors) == 0 &&
		len(f.Analyzers) == 0 && len(f.Legacy) == 0
}

// UnmarshalYAML decodes the plugins block, accepting both the kind-scoped
// canonical shape and legacy flat `plugins.<id>` entries.
func (f *PluginsFile) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Kind != yaml.MappingNode {
		return fmt.Errorf("plugins must be a mapping")
	}
	for idx := 0; idx+1 < len(value.Content); idx += 2 {
		keyNode := value.Content[idx]
		valueNode := value.Content[idx+1]
		key := strings.TrimSpace(keyNode.Value)
		if key == "" {
			continue
		}
		var block map[string]map[string]any
		switch key {
		case "detectors", "matchers", "auditors", "analyzers":
			if err := valueNode.Decode(&block); err != nil {
				return fmt.Errorf("decode plugins.%s: %w", key, err)
			}
			switch key {
			case "detectors":
				f.Detectors = mergePluginBlocks(f.Detectors, block)
			case "matchers":
				f.Matchers = mergePluginBlocks(f.Matchers, block)
			case "auditors":
				f.Auditors = mergePluginBlocks(f.Auditors, block)
			case "analyzers":
				f.Analyzers = mergePluginBlocks(f.Analyzers, block)
			}
		default:
			var legacyBlock map[string]any
			if err := valueNode.Decode(&legacyBlock); err != nil {
				return fmt.Errorf("decode plugins.%s: %w", key, err)
			}
			if f.Legacy == nil {
				f.Legacy = make(map[string]map[string]any)
			}
			f.Legacy[key] = legacyBlock
		}
	}
	return nil
}

func mergePluginBlocks(dst, src map[string]map[string]any) map[string]map[string]any {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]map[string]any, len(src))
	}
	for name, block := range src {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		dst[name] = clonePluginConfig(block)
	}
	return dst
}

// PluginCatalog describes the known component universe used to validate
// `plugins:` configuration blocks. Components maps a component kind
// (PluginKindDetector, ...) to known component names, including aliases and
// installed plugin IDs. Schemas maps "<kind>/<name>" to the component's
// advertised JSON config schema.
type PluginCatalog struct {
	Components map[string][]string
	Schemas    map[string]json.RawMessage
}

// SchemaKey builds the Schemas map key for a (kind, name) pair.
func SchemaKey(kind, name string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + "/" + strings.TrimSpace(name)
}

// ValidatePluginConfigs returns warning messages (never errors) for the
// resolved plugins configuration: deprecated legacy flat blocks, blocks that
// name no known component, and blocks with keys the component's advertised
// config schema rejects.
func ValidatePluginConfigs(cfg Resolved, catalog PluginCatalog) []string {
	warnings := make([]string, 0)

	for _, name := range sortedPluginNames(cfg.Plugins.Legacy) {
		warnings = append(warnings, fmt.Sprintf(
			"plugins.%s: flat plugin configuration is deprecated; move the block under plugins.<kind> (detectors, matchers, auditors, or analyzers)", name))
		if catalog.Components != nil && !catalogKnowsAnyKind(catalog, name) {
			warnings = append(warnings, fmt.Sprintf(
				"plugins.%s: no built-in component or installed plugin is named %q", name, name))
			continue
		}
		if schema, kind := legacySchemaForName(catalog, name); schema != nil {
			warnings = append(warnings, schemaUnknownKeyWarnings(fmt.Sprintf("plugins.%s", name), cfg.Plugins.Legacy[name], schema, kind)...)
		}
	}

	for _, bucket := range pluginKindBuckets {
		blocks := cfg.Plugins.bucketForKind(bucket.Kind)
		for _, name := range sortedPluginNames(blocks) {
			path := fmt.Sprintf("plugins.%s.%s", bucket.YAMLKey, name)
			if catalog.Components != nil && !catalogKnows(catalog, bucket.Kind, name) {
				warnings = append(warnings, fmt.Sprintf(
					"%s: no built-in component or installed plugin is named %q", path, name))
				continue
			}
			if schema, ok := catalog.Schemas[SchemaKey(bucket.Kind, name)]; ok {
				warnings = append(warnings, schemaUnknownKeyWarnings(path, blocks[name], schema, bucket.Kind)...)
			}
		}
	}
	return warnings
}

func sortedPluginNames(blocks map[string]map[string]any) []string {
	names := make([]string, 0, len(blocks))
	for name := range blocks {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func catalogKnows(catalog PluginCatalog, kind, name string) bool {
	for _, known := range catalog.Components[kind] {
		if strings.EqualFold(strings.TrimSpace(known), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

func catalogKnowsAnyKind(catalog PluginCatalog, name string) bool {
	for kind := range catalog.Components {
		if catalogKnows(catalog, kind, name) {
			return true
		}
	}
	return false
}

func legacySchemaForName(catalog PluginCatalog, name string) (json.RawMessage, string) {
	for _, bucket := range pluginKindBuckets {
		if !catalogKnows(catalog, bucket.Kind, name) {
			continue
		}
		if schema, ok := catalog.Schemas[SchemaKey(bucket.Kind, name)]; ok {
			return schema, bucket.Kind
		}
	}
	return nil, ""
}

// schemaUnknownKeyWarnings implements a minimal structural check: when the
// schema declares `additionalProperties: false`, top-level keys absent from
// `properties` produce a warning. Anything else passes; this is intentionally
// warning-only and shallow.
func schemaUnknownKeyWarnings(path string, block map[string]any, schema json.RawMessage, _ string) []string {
	if len(block) == 0 || len(schema) == 0 {
		return nil
	}
	var parsed struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		return nil
	}
	if parsed.AdditionalProperties == nil || *parsed.AdditionalProperties {
		return nil
	}
	unknown := make([]string, 0)
	for key := range block {
		if _, ok := parsed.Properties[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return []string{fmt.Sprintf("%s: unknown configuration keys not accepted by the plugin's config schema: %s", path, strings.Join(unknown, ", "))}
}
