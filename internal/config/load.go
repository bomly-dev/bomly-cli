package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
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
// error when the file does not exist or path is empty. Relative path/config
// fields inside the file are resolved relative to the file's directory.
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
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	normalizeFilePaths(&cfg, filepath.Dir(path))
	return &cfg, nil
}

func normalizeFilePaths(cfg *File, baseDir string) {
	for _, target := range []*string{cfg.Path, cfg.Config, cfg.HTTPCACertFile} {
		if target == nil || strings.TrimSpace(*target) == "" || filepath.IsAbs(*target) {
			continue
		}
		*target = filepath.Clean(filepath.Join(baseDir, *target))
	}
}

// ApplyFileConfig merges non-nil src fields into dst. File fields are pointers;
// nil means the user did not set the field, so dst is left unchanged.
func ApplyFileConfig(dst *Resolved, src File) {
	if dst == nil {
		return
	}
	dstVal := reflect.ValueOf(dst).Elem()
	srcVal := reflect.ValueOf(src)
	t := srcVal.Type()
	for i := 0; i < t.NumField(); i++ {
		sf := srcVal.Field(i)
		if sf.Kind() != reflect.Pointer || sf.IsNil() {
			continue
		}
		df := dstVal.FieldByName(t.Field(i).Name)
		if df.IsValid() && df.CanSet() {
			df.Set(sf.Elem())
		}
	}
	// InstallArgs is a slice (not a pointer) — replace when provided.
	if len(src.InstallArgs) > 0 {
		dst.InstallArgs = append([]string(nil), src.InstallArgs...)
	}
	// FailOn is a custom-unmarshaled slice (FailOnList) — replace when set.
	if len(src.FailOn) > 0 {
		dst.FailOn = append([]string(nil), src.FailOn...)
	}
	if len(src.FailOnScopes) > 0 {
		dst.FailOnScopes = append([]string(nil), src.FailOnScopes...)
	}
	if len(src.AllowVulnerabilityIDs) > 0 {
		dst.AllowVulnerabilityIDs = append([]string(nil), src.AllowVulnerabilityIDs...)
	}
	if len(src.AllowLicenses) > 0 {
		dst.AllowLicenses = append([]string(nil), src.AllowLicenses...)
	}
	if len(src.DenyLicenses) > 0 {
		dst.DenyLicenses = append([]string(nil), src.DenyLicenses...)
	}
	if len(src.LicenseExemptPackages) > 0 {
		dst.LicenseExemptPackages = append([]string(nil), src.LicenseExemptPackages...)
	}
	if len(src.DenyPackages) > 0 {
		dst.DenyPackages = append([]string(nil), src.DenyPackages...)
	}
	if len(src.DenyGroups) > 0 {
		dst.DenyGroups = append([]string(nil), src.DenyGroups...)
	}
	if len(src.ProtectedPackages) > 0 {
		dst.ProtectedPackages = append([]string(nil), src.ProtectedPackages...)
	}
	if len(src.Outputs) > 0 {
		dst.Outputs = append([]string(nil), src.Outputs...)
	}
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
	// Verbose is a legacy shorthand; map it to Verbosity=1 if not already set.
	if src.Verbose != nil && *src.Verbose && dst.Verbosity == 0 {
		dst.Verbosity = 1
	}
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
	// Both --audit and --reachability operate on vulnerability data the
	// matchers attach during enrichment. Without --enrich the matchers
	// don't run and these flags would silently produce zero findings /
	// no annotations, which is a confusing footgun. Require --enrich up
	// front so the user gets a clear error instead.
	if cfg.Audit && !cfg.Enrich {
		return fmt.Errorf("--audit requires --enrich")
	}
	if cfg.Reachability && !cfg.Enrich {
		return fmt.Errorf("--reachability requires --enrich")
	}
	if len(cfg.AllowLicenses) > 0 && len(cfg.DenyLicenses) > 0 {
		return fmt.Errorf("--allow-license cannot be combined with --deny-license")
	}
	for _, scope := range cfg.FailOnScopes {
		switch strings.ToLower(strings.TrimSpace(scope)) {
		case "", "runtime", "development", "unknown":
		default:
			return fmt.Errorf("unsupported --fail-on-scope value %q (accepted: runtime, development, unknown)", scope)
		}
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
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
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
