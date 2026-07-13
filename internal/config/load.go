package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// UserConfigPath returns the path to the user-level config file (~/.bomly/config.yaml).
// Returns an empty string (no error) when the home directory cannot be determined.
func UserConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		if strings.TrimSpace(err.Error()) == "" {
			return "", nil
		}
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	if strings.TrimSpace(home) == "" {
		return "", nil
	}
	return filepath.Join(home, ".bomly", "config.yaml"), nil
}

// LoadFile reads and parses a YAML config file at path. Returns nil with no
// error when the file does not exist or path is empty. Relative path fields
// inside the file are resolved relative to the file's directory.
func LoadFile(path string) (*File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg File
	if err := rejectLegacyFlatKeys(data); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil && err != io.EOF {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	normalizeFilePaths(&cfg, filepath.Dir(path))
	return &cfg, nil
}

func normalizeFilePaths(cfg *File, baseDir string) {
	for _, target := range []*string{cfg.Target.Path, cfg.Network.CACertFile} {
		if target == nil || strings.TrimSpace(*target) == "" || filepath.IsAbs(*target) {
			continue
		}
		*target = filepath.Clean(filepath.Join(baseDir, *target))
	}
}

// ApplyFileConfig merges explicitly set src leaves into dst.
func ApplyFileConfig(dst *Resolved, src File) {
	if dst == nil {
		return
	}
	applyFileLeaves(reflect.ValueOf(dst).Elem(), reflect.ValueOf(src))
	if len(src.Plugins) > 0 {
		if dst.Plugins == nil {
			dst.Plugins = make(map[string]map[string]any, len(src.Plugins))
		}
		for id, pluginConfig := range src.Plugins {
			trimmedID := strings.TrimSpace(id)
			if trimmedID == "" {
				continue
			}
			dst.Plugins[trimmedID] = clonePluginConfig(pluginConfig)
		}
	}
}

func applyFileLeaves(dst reflect.Value, src reflect.Value) {
	srcType := src.Type()
	for i := 0; i < src.NumField(); i++ {
		fieldType := srcType.Field(i)
		srcField := src.Field(i)
		resolvedName := fieldType.Tag.Get("resolved")
		if resolvedName != "" {
			if srcField.Kind() == reflect.Pointer && !srcField.IsNil() {
				setResolvedField(dst.FieldByName(resolvedName), srcField.Elem())
			}
			continue
		}
		if srcField.Kind() == reflect.Struct {
			applyFileLeaves(dst, srcField)
		}
	}
}

func setResolvedField(dst reflect.Value, src reflect.Value) {
	if !dst.IsValid() || !dst.CanSet() {
		return
	}
	if src.Type().ConvertibleTo(dst.Type()) {
		src = src.Convert(dst.Type())
	}
	if src.Kind() == reflect.Slice {
		clone := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		reflect.Copy(clone, src)
		src = clone
	}
	if src.Type().AssignableTo(dst.Type()) {
		dst.Set(src)
	}
}

func rejectLegacyFlatKeys(data []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return err
	}
	if len(document.Content) == 0 {
		return nil
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}

	legacyPaths := LegacyMigrationPaths()
	canonicalRoots := canonicalRootKeys()
	for idx := 0; idx+1 < len(root.Content); idx += 2 {
		keyNode := root.Content[idx]
		valueNode := root.Content[idx+1]
		key := strings.TrimSpace(keyNode.Value)
		if key == "config" {
			return fmt.Errorf("config file key %q is no longer supported; use --config to select an explicit file", key)
		}
		nestedPath, ok := legacyPaths[key]
		if !ok {
			continue
		}
		if _, isCanonicalRoot := canonicalRoots[key]; isCanonicalRoot && valueNode.Kind == yaml.MappingNode {
			continue
		}
		return fmt.Errorf("flat config key %q is no longer supported; use %q", key, nestedPath)
	}
	return nil
}

// LegacyMigrationPaths returns former flat YAML keys and their replacements.
func LegacyMigrationPaths() map[string]string {
	paths := make(map[string]string)
	collectLegacyConfigPaths(reflect.TypeOf(File{}), "", paths)
	paths["config"] = "--config"
	paths["verbose"] = "logging.verbosity"
	return paths
}

// YAMLPathsByResolvedField returns nested YAML paths keyed by flat runtime field.
func YAMLPathsByResolvedField() map[string]string {
	paths := make(map[string]string)
	collectResolvedConfigPaths(reflect.TypeOf(File{}), "", paths)
	return paths
}

func collectLegacyConfigPaths(t reflect.Type, prefix string, paths map[string]string) {
	for idx := 0; idx < t.NumField(); idx++ {
		field := t.Field(idx)
		key := yamlTagName(field.Tag.Get("yaml"))
		if key == "" || key == "-" {
			continue
		}
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if legacy := field.Tag.Get("legacy"); legacy != "" {
			paths[legacy] = path
		}
		if field.Type.Kind() == reflect.Struct {
			collectLegacyConfigPaths(field.Type, path, paths)
		}
	}
}

func collectResolvedConfigPaths(t reflect.Type, prefix string, paths map[string]string) {
	for idx := 0; idx < t.NumField(); idx++ {
		field := t.Field(idx)
		key := yamlTagName(field.Tag.Get("yaml"))
		if key == "" || key == "-" {
			continue
		}
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if resolved := field.Tag.Get("resolved"); resolved != "" {
			paths[resolved] = path
		}
		if field.Type.Kind() == reflect.Struct {
			collectResolvedConfigPaths(field.Type, path, paths)
		}
	}
}

func canonicalRootKeys() map[string]struct{} {
	keys := make(map[string]struct{})
	fileType := reflect.TypeOf(File{})
	for idx := 0; idx < fileType.NumField(); idx++ {
		key := yamlTagName(fileType.Field(idx).Tag.Get("yaml"))
		if key != "" && key != "-" {
			keys[key] = struct{}{}
		}
	}
	return keys
}

func yamlTagName(tag string) string {
	if idx := strings.Index(tag, ","); idx >= 0 {
		tag = tag[:idx]
	}
	return tag
}

// ApplyEnvOverrides reads the environment variables named in Resolved's env
// struct tags and overwrites the corresponding dst fields.
func ApplyEnvOverrides(dst *Resolved) {
	if dst == nil {
		return
	}
	v := reflect.ValueOf(dst).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		key := t.Field(i).Tag.Get("env")
		if key == "" {
			continue
		}
		val, ok := os.LookupEnv(key)
		if !ok {
			if alias := t.Field(i).Tag.Get("envalias"); alias != "" {
				val, ok = os.LookupEnv(alias)
			}
		}
		if !ok {
			continue
		}
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			fv.SetString(val)
		case reflect.Bool:
			if b, ok := parseBool(val); ok {
				fv.SetBool(b)
			}
		case reflect.Int:
			if t.Field(i).Name == "Verbosity" {
				applyVerbosityEnv(fv, val)
			} else if parsed, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				fv.SetInt(int64(parsed))
			}
		case reflect.Slice:
			fv.Set(reflect.ValueOf(parseCSV(val)))
		}
	}
}

// ApplyDefaults fills in zero-value fields with their documented defaults,
// driven by the `default` struct tags on Resolved.
func ApplyDefaults(cfg *Resolved) {
	if cfg == nil {
		return
	}
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		def := t.Field(i).Tag.Get("default")
		if def == "" {
			continue
		}
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			if strings.TrimSpace(fv.String()) == "" {
				fv.SetString(def)
			}
		case reflect.Bool:
			if !fv.Bool() {
				if b, ok := parseBool(def); ok {
					fv.SetBool(b)
				}
			}
		case reflect.Int:
			if fv.Int() == 0 {
				if parsed, err := strconv.Atoi(strings.TrimSpace(def)); err == nil {
					fv.SetInt(int64(parsed))
				}
			}
		}
	}
}

// Validate returns an error if cfg contains mutually exclusive options.
func Validate(cfg Resolved) error {
	if cfg.Interactive && strings.TrimSpace(cfg.Format) != "" {
		return fmt.Errorf("--interactive cannot be combined with --format")
	}
	if cfg.Quiet && cfg.Verbosity > 0 {
		return fmt.Errorf("--quiet cannot be combined with --verbose")
	}
	// Both --audit and --analyze operate on vulnerability data the
	// matchers attach during enrichment. Without --enrich the matchers
	// don't run and these flags would silently produce zero findings /
	// no annotations, which is a confusing footgun. Require --enrich up
	// front so the user gets a clear error instead.
	if cfg.Audit && !cfg.Enrich {
		return fmt.Errorf("--audit requires --enrich")
	}
	if cfg.Analyze && !cfg.Enrich {
		return fmt.Errorf("--analyze requires --enrich")
	}
	if cfg.MaxDepth < 0 {
		return fmt.Errorf("--max-depth must be a positive depth or 0 for unlimited")
	}
	if len(cfg.ExcludePaths) > 0 && !cfg.Recursive {
		return fmt.Errorf("--exclude requires --recursive")
	}
	if cfg.Recursive && strings.TrimSpace(cfg.Image) != "" {
		return fmt.Errorf("--recursive cannot be combined with --image")
	}
	if cfg.Recursive && cfg.SBOM {
		return fmt.Errorf("--recursive cannot be combined with --sbom")
	}
	for _, pattern := range cfg.ExcludePaths {
		normalized := strings.TrimSpace(strings.ReplaceAll(pattern, "\\", "/"))
		if normalized == "" {
			return fmt.Errorf("invalid --exclude pattern %q: pattern is empty", pattern)
		}
		if _, err := path.Match(normalized, "probe"); err != nil {
			return fmt.Errorf("invalid --exclude pattern %q: %w", pattern, err)
		}
	}
	if len(cfg.AllowLicenses) > 0 && len(cfg.DenyLicenses) > 0 {
		return fmt.Errorf("--allow-license cannot be combined with --deny-license")
	}
	if threshold := strings.TrimSpace(cfg.TyposquatThreshold); threshold != "" {
		if _, err := strconv.ParseFloat(threshold, 64); err != nil {
			return fmt.Errorf("invalid --typosquat-threshold %q", cfg.TyposquatThreshold)
		}
	}
	switch strings.ToLower(strings.TrimSpace(cfg.TyposquatMode)) {
	case "", "warn", "fail":
	default:
		return fmt.Errorf("unsupported --typosquat-mode value %q (accepted: warn, fail)", cfg.TyposquatMode)
	}
	if err := validateProxyURL(cfg.HTTPProxy); err != nil {
		return err
	}
	if err := validateProxyFields(cfg); err != nil {
		return err
	}
	return nil
}

func validateProxyURL(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := parseProxyURL(value)
	if err != nil {
		return err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid http_proxy URL: must be absolute")
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "http", "https", "socks", "socks5":
	default:
		return fmt.Errorf("unsupported http_proxy scheme %q (accepted: http, https, socks5)", parsed.Scheme)
	}
	return nil
}

func parseProxyURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("invalid http_proxy URL: %w", redactURLParseError(err))
	}
	return parsed, nil
}

func redactURLParseError(err error) error {
	if urlErr, ok := errors.AsType[*url.Error](err); ok && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

func validateProxyFields(cfg Resolved) error {
	switch strings.ToLower(strings.TrimSpace(cfg.HTTPProxyType)) {
	case "", "http", "https", "socks", "socks5":
	default:
		return fmt.Errorf("unsupported http_proxy_type value %q (accepted: http, https, socks5)", cfg.HTTPProxyType)
	}
	if strings.TrimSpace(cfg.HTTPProxyHost) == "" {
		if cfg.HTTPProxyPort != 0 {
			return fmt.Errorf("http_proxy_port requires http_proxy_host")
		}
		if strings.TrimSpace(cfg.HTTPProxyUsername) != "" || strings.TrimSpace(cfg.HTTPProxyPassword) != "" {
			return fmt.Errorf("http_proxy_username and http_proxy_password require http_proxy_host")
		}
		return nil
	}
	if cfg.HTTPProxyPort <= 0 || cfg.HTTPProxyPort > 65535 {
		return fmt.Errorf("http_proxy_port must be between 1 and 65535")
	}
	return nil
}

func clonePluginConfig(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		out := make(map[string]any, len(value))
		for key, item := range value {
			out[key] = item
		}
		return out
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		copyValue := make(map[string]any, len(value))
		for key, item := range value {
			copyValue[key] = item
		}
		return copyValue
	}
	return out
}

func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

// applyVerbosityEnv applies a BOMLY_VERBOSE env var value to the Verbosity field.
// It accepts numeric levels (0–3) and bool-style truthy/falsy strings.
func applyVerbosityEnv(fv reflect.Value, val string) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "on":
		if fv.Int() == 0 {
			fv.SetInt(1)
		}
	case "2":
		fv.SetInt(2)
	case "3":
		fv.SetInt(3)
	case "0", "false", "no", "off":
		fv.SetInt(0)
	}
}

func parseCSV(value string) []string {
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, trimmed)
	}
	return items
}
