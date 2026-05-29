package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileAndEnvProxyPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
http_proxy: http://file-proxy.example:8080
http_no_proxy: file.internal
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
	if got := resolved.Plugins["acme.matcher"]["api_base"]; got != "https://api.file.example" {
		t.Fatalf("plugin api_base = %#v", got)
	}

	t.Setenv("BOMLY_HTTP_PROXY", "http://env-proxy.example:8080")
	t.Setenv("BOMLY_HTTP_NO_PROXY", "env.internal")
	ApplyEnvOverrides(&resolved)
	if resolved.HTTPProxy != "http://env-proxy.example:8080" {
		t.Fatalf("HTTPProxy after env = %q", resolved.HTTPProxy)
	}
	if resolved.HTTPNoProxy != "env.internal" {
		t.Fatalf("HTTPNoProxy after env = %q", resolved.HTTPNoProxy)
	}
	if got := resolved.Plugins["acme.matcher"]["batch_size"]; got != float64(10) {
		t.Fatalf("plugin batch_size = %#v", got)
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
