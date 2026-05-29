package sdk

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewHTTPClientExplicitProxy(t *testing.T) {
	client, err := NewHTTPClient(HTTPClientConfig{
		ProxyURL: "http://proxy.example:8080",
		Timeout:  3 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	if client.Timeout != 3*time.Second {
		t.Fatalf("Timeout = %v, want 3s", client.Timeout)
	}
	proxyURL := proxyForRequest(t, client, "http://service.example/v1")
	if proxyURL == nil || proxyURL.String() != "http://proxy.example:8080" {
		t.Fatalf("proxy = %v, want http://proxy.example:8080", proxyURL)
	}
}

func TestNewHTTPClientNoProxyBypass(t *testing.T) {
	client, err := NewHTTPClient(HTTPClientConfig{
		ProxyURL: "http://proxy.example:8080",
		NoProxy:  ".corp.example",
	})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	if proxyURL := proxyForRequest(t, client, "http://service.corp.example/v1"); proxyURL != nil {
		t.Fatalf("proxy = %v, want bypass", proxyURL)
	}
}

func TestNewHTTPClientRejectsInvalidProxy(t *testing.T) {
	if _, err := NewHTTPClient(HTTPClientConfig{ProxyURL: "proxy.example:8080"}); err == nil {
		t.Fatal("NewHTTPClient() error = nil, want invalid proxy error")
	}
}

func TestHTTPClientConfigFromEnvAndStandardFallback(t *testing.T) {
	t.Setenv(EnvHTTPProxy, "http://bomly-proxy.example:8080")
	t.Setenv(EnvHTTPNoProxy, "internal.example")
	cfg := HTTPClientConfigFromEnv()
	if cfg.ProxyURL != "http://bomly-proxy.example:8080" {
		t.Fatalf("ProxyURL = %q", cfg.ProxyURL)
	}
	if cfg.NoProxy != "internal.example" {
		t.Fatalf("NoProxy = %q", cfg.NoProxy)
	}

	t.Setenv(EnvHTTPProxy, "")
	t.Setenv(EnvHTTPNoProxy, "")
	t.Setenv("HTTP_PROXY", "http://standard-proxy.example:8080")
	client, err := NewHTTPClient(HTTPClientConfigFromEnv())
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	proxyURL := proxyForRequest(t, client, "http://service.example/v1")
	if proxyURL == nil || proxyURL.String() != "http://standard-proxy.example:8080" {
		t.Fatalf("proxy = %v, want standard env proxy", proxyURL)
	}
}

func TestDecodePluginConfigFromEnv(t *testing.T) {
	type pluginConfig struct {
		APIBase string `json:"api_base"`
		Enabled bool   `json:"enabled"`
	}
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(map[string]any{"api_base": "https://api.example.com", "enabled": true})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(EnvPluginConfigFile, path)

	var cfg pluginConfig
	if err := DecodePluginConfigFromEnv(&cfg); err != nil {
		t.Fatalf("DecodePluginConfigFromEnv() error = %v", err)
	}
	if cfg.APIBase != "https://api.example.com" || !cfg.Enabled {
		t.Fatalf("decoded config = %#v", cfg)
	}
}

func proxyForRequest(t *testing.T, client *http.Client, rawURL string) *url.URL {
	t.Helper()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy == nil {
		t.Fatalf("client transport proxy unavailable")
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	proxyURL, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("proxy func error = %v", err)
	}
	return proxyURL
}
