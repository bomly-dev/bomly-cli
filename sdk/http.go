package sdk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
)

const (
	// EnvHTTPProxy is Bomly's explicit outbound HTTP proxy environment variable.
	EnvHTTPProxy = "BOMLY_HTTP_PROXY"
	// EnvHTTPNoProxy is Bomly's explicit proxy bypass list environment variable.
	EnvHTTPNoProxy = "BOMLY_HTTP_NO_PROXY"
	// EnvPluginConfigFile points external plugins at their per-plugin JSON config.
	EnvPluginConfigFile = "BOMLY_PLUGIN_CONFIG_FILE"
	// EnvPluginID identifies the managed plugin currently being executed.
	EnvPluginID = "BOMLY_PLUGIN_ID"
)

// HTTPClientConfig configures Bomly's shared outbound HTTP client.
type HTTPClientConfig struct {
	ProxyURL string
	NoProxy  string
	Timeout  time.Duration
}

// HTTPClientConfigFromEnv returns Bomly-specific HTTP client settings from
// environment variables. Standard HTTP_PROXY, HTTPS_PROXY, and NO_PROXY are
// still honored by NewHTTPClient when Bomly-specific values are absent.
func HTTPClientConfigFromEnv() HTTPClientConfig {
	return HTTPClientConfig{
		ProxyURL: strings.TrimSpace(os.Getenv(EnvHTTPProxy)),
		NoProxy:  strings.TrimSpace(os.Getenv(EnvHTTPNoProxy)),
	}
}

// NewHTTPClient creates an outbound HTTP client using Go's default transport
// behavior plus Bomly's proxy configuration.
func NewHTTPClient(config HTTPClientConfig) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxy, err := proxyFunc(config)
	if err != nil {
		return nil, err
	}
	transport.Proxy = proxy
	return &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}, nil
}

func proxyFunc(config HTTPClientConfig) (func(*http.Request) (*url.URL, error), error) {
	proxyURL := strings.TrimSpace(config.ProxyURL)
	noProxy := strings.TrimSpace(config.NoProxy)
	if proxyURL == "" {
		return http.ProxyFromEnvironment, nil
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("proxy URL must be absolute")
	}
	urlProxy := (&httpproxy.Config{
		HTTPProxy:  proxyURL,
		HTTPSProxy: proxyURL,
		NoProxy:    noProxy,
	}).ProxyFunc()
	return func(req *http.Request) (*url.URL, error) {
		return urlProxy(req.URL)
	}, nil
}

// RawPluginConfigFromEnv reads the per-plugin JSON config file named by
// BOMLY_PLUGIN_CONFIG_FILE. It returns nil when no plugin config file is set.
func RawPluginConfigFromEnv() ([]byte, error) {
	path := strings.TrimSpace(os.Getenv(EnvPluginConfigFile))
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plugin config: %w", err)
	}
	return data, nil
}

// DecodePluginConfigFromEnv decodes the per-plugin JSON config file into target.
func DecodePluginConfigFromEnv(target any) error {
	data, err := RawPluginConfigFromEnv()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if target == nil {
		return fmt.Errorf("plugin config target is nil")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode plugin config: %w", err)
	}
	return nil
}
