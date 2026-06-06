package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFileAndEnvProxyPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
network:
  proxy:
    url: http://file-proxy.example:8080
    no_proxy: file.internal
    type: socks5
    host: split-proxy.example
    port: 1080
    username: agent
    password: secret
  ca_cert_file: certs/proxy-ca.pem
plugins:
  acme.matcher:
    api_base: https://api.file.example
    batch_size: 10
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fileCfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	var resolved Resolved
	ApplyFileConfig(&resolved, *fileCfg)
	if resolved.HTTPProxy != "http://file-proxy.example:8080" {
		t.Fatalf("HTTPProxy = %q", resolved.HTTPProxy)
	}
	if resolved.HTTPNoProxy != "file.internal" {
		t.Fatalf("HTTPNoProxy = %q", resolved.HTTPNoProxy)
	}
	if resolved.HTTPProxyType != "socks5" || resolved.HTTPProxyHost != "split-proxy.example" || resolved.HTTPProxyPort != 1080 {
		t.Fatalf("decomposed proxy config = %#v", resolved)
	}
	if resolved.HTTPProxyUsername != "agent" || resolved.HTTPProxyPassword != "secret" {
		t.Fatalf("proxy auth config = %#v", resolved)
	}
	if want := filepath.Join(filepath.Dir(path), "certs", "proxy-ca.pem"); resolved.HTTPCACertFile != want {
		t.Fatalf("HTTPCACertFile = %q, want %q", resolved.HTTPCACertFile, want)
	}
	if got := resolved.Plugins["acme.matcher"]["api_base"]; got != "https://api.file.example" {
		t.Fatalf("plugin api_base = %#v", got)
	}

	t.Setenv("BOMLY_HTTP_PROXY", "http://env-proxy.example:8080")
	t.Setenv("BOMLY_HTTP_NO_PROXY", "env.internal")
	t.Setenv("BOMLY_HTTP_PROXY_HOST", "env-split-proxy.example")
	t.Setenv("BOMLY_HTTP_PROXY_PORT", "3128")
	ApplyEnvOverrides(&resolved)
	if resolved.HTTPProxy != "http://env-proxy.example:8080" {
		t.Fatalf("HTTPProxy after env = %q", resolved.HTTPProxy)
	}
	if resolved.HTTPNoProxy != "env.internal" {
		t.Fatalf("HTTPNoProxy after env = %q", resolved.HTTPNoProxy)
	}
	if resolved.HTTPProxyHost != "env-split-proxy.example" || resolved.HTTPProxyPort != 3128 {
		t.Fatalf("decomposed proxy after env = %#v", resolved)
	}
	if got := resolved.Plugins["acme.matcher"]["batch_size"]; got != float64(10) {
		t.Fatalf("plugin batch_size = %#v", got)
	}
}

func TestLoadFileNestedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
target:
  path: fixture
  container: alpine:3.20
  url: https://example.com/acme/repo.git
  ref: main
  sbom: true
analysis:
  enrich: true
  audit: true
  reachability: true
  install_first: true
  install_args: [--offline]
components:
  ecosystems: go,npm
  detectors: gomod
  auditors: policy
  matchers: osv
  analyzers: govulncheck
policy:
  fail_on: [high, reachable]
  fail_on_scopes: [runtime]
  allow_vulnerability_ids: [CVE-2026-0001]
  allow_licenses: [MIT]
  deny_licenses: [GPL-3.0]
  license_exempt_packages: [pkg:golang/example.com/exempt@v1.0.0]
  deny_packages: [pkg:golang/example.com/denied@v1.0.0]
  deny_groups: [example.com/private]
  protected_packages: [github.com/acme/core]
  typosquat_threshold: "0.95"
  typosquat_mode: fail
  warn_only: true
output:
  format: json
  outputs: [spdx=sbom.json]
  interactive: true
logging:
  quiet: true
  verbosity: 2
matchers:
  osv:
    api_base: https://osv.example
    cache_dir: cache/osv
    cache_ttl: 1h
    kev:
      cache_dir: cache/kev
      cache_ttl: 2h
  scorecard:
    api_base: https://scorecard.example
    cache_dir: cache/scorecard
    cache_ttl: 4h
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fileCfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	var resolved Resolved
	ApplyFileConfig(&resolved, *fileCfg)

	if want := filepath.Join(filepath.Dir(path), "fixture"); resolved.Path != want {
		t.Fatalf("Path = %q, want %q", resolved.Path, want)
	}
	if resolved.Container != "alpine:3.20" || resolved.URL == "" || resolved.Ref != "main" || !resolved.SBOM {
		t.Fatalf("target config = %#v", resolved)
	}
	if !resolved.Enrich || !resolved.Audit || !resolved.Reachability || !resolved.InstallFirst {
		t.Fatalf("analysis config = %#v", resolved)
	}
	if len(resolved.InstallArgs) != 1 || resolved.InstallArgs[0] != "--offline" {
		t.Fatalf("InstallArgs = %#v", resolved.InstallArgs)
	}
	if resolved.Ecosystems != "go,npm" || resolved.Detectors != "gomod" || resolved.Auditors != "policy" || resolved.Matchers != "osv" || resolved.Analyzers != "govulncheck" {
		t.Fatalf("component config = %#v", resolved)
	}
	if len(resolved.FailOn) != 2 || len(resolved.FailOnScopes) != 1 || len(resolved.AllowVulnerabilityIDs) != 1 || len(resolved.AllowLicenses) != 1 || len(resolved.DenyLicenses) != 1 || len(resolved.LicenseExemptPackages) != 1 || len(resolved.DenyPackages) != 1 || len(resolved.DenyGroups) != 1 || len(resolved.ProtectedPackages) != 1 {
		t.Fatalf("policy config = %#v", resolved)
	}
	if resolved.TyposquatThreshold != "0.95" || resolved.TyposquatMode != "fail" || !resolved.WarnOnly {
		t.Fatalf("typosquat config = %#v", resolved)
	}
	if resolved.Format != "json" || len(resolved.Outputs) != 1 || !resolved.Interactive || !resolved.Quiet || resolved.Verbosity != 2 {
		t.Fatalf("output/logging config = %#v", resolved)
	}
	if resolved.OsvAPIBase != "https://osv.example" || resolved.OsvCacheTTL != "1h" || resolved.KEVCacheTTL != "2h" || resolved.ScorecardAPIBase != "https://scorecard.example" || resolved.ScorecardCacheTTL != "4h" {
		t.Fatalf("matcher config = %#v", resolved)
	}
}

func TestApplyFileConfigClearsInheritedLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
analysis:
  enrich: false
  install_args: []
policy:
  fail_on: []
  allow_licenses: []
output:
  interactive: false
  outputs: []
logging:
  verbosity: 0
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	fileCfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	resolved := Resolved{
		Enrich:        true,
		InstallArgs:   []string{"--offline"},
		FailOn:        []string{"high"},
		AllowLicenses: []string{"MIT"},
		Interactive:   true,
		Outputs:       []string{"spdx=sbom.json"},
		Verbosity:     2,
	}
	ApplyFileConfig(&resolved, *fileCfg)
	if resolved.Enrich || resolved.Interactive || resolved.Verbosity != 0 {
		t.Fatalf("expected explicit zero values to override inherited values, got %#v", resolved)
	}
	if len(resolved.InstallArgs) != 0 || len(resolved.FailOn) != 0 || len(resolved.AllowLicenses) != 0 || len(resolved.Outputs) != 0 {
		t.Fatalf("expected explicit empty lists to clear inherited values, got %#v", resolved)
	}
}

func TestLoadFileRejectsLegacyAndUnknownKeys(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "flat key", yaml: "http_proxy: http://proxy.example:8080\n", want: `use "network.proxy.url"`},
		{name: "flat matcher selector", yaml: "matchers: osv\n", want: `use "components.matchers"`},
		{name: "config key", yaml: "config: other.yaml\n", want: "use --config"},
		{name: "verbose shorthand", yaml: "verbose: true\n", want: `use "logging.verbosity"`},
		{name: "unknown root", yaml: "unknown: true\n", want: "field unknown not found"},
		{name: "unknown nested", yaml: "network:\n  proxy:\n    unknown: true\n", want: "field unknown not found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o644); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := LoadFile(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadFile() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestApplyFileConfigMergesPluginConfigsByID(t *testing.T) {
	resolved := Resolved{}
	ApplyFileConfig(&resolved, File{Plugins: map[string]map[string]any{
		"acme.one": {"value": "one"},
	}})
	ApplyFileConfig(&resolved, File{Plugins: map[string]map[string]any{
		"acme.two": {"value": "two"},
	}})
	if _, ok := resolved.Plugins["acme.one"]; !ok {
		t.Fatalf("expected first plugin config to remain")
	}
	if got := resolved.Plugins["acme.two"]["value"]; got != "two" {
		t.Fatalf("second plugin config = %#v", got)
	}
}
