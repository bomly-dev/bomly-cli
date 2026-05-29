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
		ConfigPath:  "/tmp/bomly.yaml",
		HTTPProxy:   "http://proxy.example:8080",
		HTTPNoProxy: "localhost,.corp.example",
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
	if values[sdk.EnvHTTPProxy] != "http://proxy.example:8080" || values["HTTPS_PROXY"] != "http://proxy.example:8080" {
		t.Fatalf("proxy env = %#v", values)
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

func envMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		out[key] = value
	}
	return out
}
