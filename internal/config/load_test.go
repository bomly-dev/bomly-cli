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
http_proxy_type: socks5
http_proxy_host: split-proxy.example
http_proxy_port: 1080
http_proxy_username: agent
http_proxy_password: secret
http_ca_cert_file: certs/proxy-ca.pem
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
