package plugin

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestPluginEnvIncludesProxyAndPluginConfig(t *testing.T) {
	env, cleanup, err := pluginEnv(LaunchOptions{
		ConfigPath:        "/tmp/bomly.yaml",
		HTTPProxyType:     "socks5",
		HTTPProxyHost:     "proxy.example",
		HTTPProxyPort:     1080,
		HTTPProxyUsername: "agent",
		HTTPProxyPassword: "secret",
		HTTPNoProxy:       "localhost,.corp.example",
		HTTPCACertFile:    "/tmp/proxy-ca.pem",
		PluginConfigs: map[string]map[string]any{
			"acme.matcher": {"api_base": "https://api.example.com"},
		},
	}, "acme.matcher")
	if err != nil {
		t.Fatalf("pluginEnv() error = %v", err)
	}
	defer cleanup()

	values := envMap(env)
	if values[EnvPluginAPIVersion] != sdk.PluginAPIVersion {
		t.Fatalf("api version env = %q", values[EnvPluginAPIVersion])
	}
	if values[EnvPluginConfig] != "/tmp/bomly.yaml" {
		t.Fatalf("config env = %q", values[EnvPluginConfig])
	}
	if values[sdk.EnvPluginID] != "acme.matcher" {
		t.Fatalf("plugin id env = %q", values[sdk.EnvPluginID])
	}
	if values[sdk.EnvHTTPProxy] != "socks5://agent:secret@proxy.example:1080" || values["HTTPS_PROXY"] != "socks5://agent:secret@proxy.example:1080" {
		t.Fatalf("proxy env = %#v", values)
	}
	if values[sdk.EnvHTTPProxyType] != "socks5" || values[sdk.EnvHTTPProxyHost] != "proxy.example" || values[sdk.EnvHTTPProxyPort] != "1080" {
		t.Fatalf("split proxy env = %#v", values)
	}
	if values[sdk.EnvHTTPProxyUsername] != "agent" || values[sdk.EnvHTTPProxyPassword] != "secret" {
		t.Fatalf("proxy auth env = %#v", values)
	}
	if values[sdk.EnvHTTPCACertFile] != "/tmp/proxy-ca.pem" {
		t.Fatalf("CA cert env = %#v", values)
	}
	if values[sdk.EnvHTTPNoProxy] != "localhost,.corp.example" || values["NO_PROXY"] != "localhost,.corp.example" {
		t.Fatalf("no-proxy env = %#v", values)
	}

	configPath := values[sdk.EnvPluginConfigFile]
	if configPath == "" {
		t.Fatalf("missing plugin config file env")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read plugin config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode plugin config: %v", err)
	}
	if cfg["api_base"] != "https://api.example.com" {
		t.Fatalf("plugin config = %#v", cfg)
	}
	cleanup()
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("expected cleanup to remove config file, stat err = %v", err)
	}
}

func TestPluginEnvForwardsStandardProxyEnvWhenBomlyProxyUnset(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://standard.example:8080")
	t.Setenv("NO_PROXY", "localhost")
	env, cleanup, err := pluginEnv(LaunchOptions{}, "acme.matcher")
	if err != nil {
		t.Fatalf("pluginEnv() error = %v", err)
	}
	defer cleanup()
	values := envMap(env)
	if values["HTTP_PROXY"] != "http://standard.example:8080" {
		t.Fatalf("HTTP_PROXY = %q", values["HTTP_PROXY"])
	}
	if values["NO_PROXY"] != "localhost" {
		t.Fatalf("NO_PROXY = %q", values["NO_PROXY"])
	}
}

func TestPluginEnvOnlyWritesSelectedPluginConfig(t *testing.T) {
	env, cleanup, err := pluginEnv(LaunchOptions{
		PluginConfigs: map[string]map[string]any{
			"acme.matcher": {"token": "selected-secret"},
			"other.plugin": {"token": "other-secret"},
		},
	}, "acme.matcher")
	if err != nil {
		t.Fatalf("pluginEnv() error = %v", err)
	}
	defer cleanup()

	values := envMap(env)
	configPath := values[sdk.EnvPluginConfigFile]
	if configPath == "" {
		t.Fatal("missing plugin config file env")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read plugin config: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "selected-secret") {
		t.Fatalf("selected plugin config missing: %s", text)
	}
	if strings.Contains(text, "other-secret") || strings.Contains(text, "other.plugin") {
		t.Fatalf("unrelated plugin config leaked: %s", text)
	}
}

func envMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		out[key] = value
	}
	return out
}
