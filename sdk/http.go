package sdk

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
)

const (
	// EnvHTTPProxy is Bomly's explicit outbound HTTP proxy environment variable.
	EnvHTTPProxy = "BOMLY_HTTP_PROXY"
	// EnvHTTPNoProxy is Bomly's explicit proxy bypass list environment variable.
	EnvHTTPNoProxy = "BOMLY_HTTP_NO_PROXY"
	// EnvHTTPProxyType is Bomly's explicit outbound proxy type.
	EnvHTTPProxyType = "BOMLY_HTTP_PROXY_TYPE"
	// EnvHTTPProxyHost is Bomly's explicit outbound proxy host.
	EnvHTTPProxyHost = "BOMLY_HTTP_PROXY_HOST"
	// EnvHTTPProxyPort is Bomly's explicit outbound proxy port.
	EnvHTTPProxyPort = "BOMLY_HTTP_PROXY_PORT"
	// EnvHTTPProxyUsername is Bomly's explicit outbound proxy username.
	EnvHTTPProxyUsername = "BOMLY_HTTP_PROXY_USERNAME"
	// EnvHTTPProxyPassword is Bomly's explicit outbound proxy password.
	EnvHTTPProxyPassword = "BOMLY_HTTP_PROXY_PASSWORD"
	// EnvHTTPCACertFile points to an additional PEM certificate chain for outbound HTTPS.
	EnvHTTPCACertFile = "BOMLY_HTTP_CA_CERT_FILE"
	// EnvPluginConfigFile points external plugins at their per-plugin JSON config.
	EnvPluginConfigFile = "BOMLY_PLUGIN_CONFIG_FILE"
	// EnvPluginID identifies the managed plugin currently being executed.
	EnvPluginID = "BOMLY_PLUGIN_ID"
)

// HTTPClientConfig configures Bomly's shared outbound HTTP client.
type HTTPClientConfig struct {
	ProxyURL      string
	NoProxy       string
	ProxyType     string
	ProxyHost     string
	ProxyPort     int
	ProxyUsername string
	ProxyPassword string
	CACertFile    string
	Timeout       time.Duration
}

// HTTPClientConfigFromEnv returns Bomly-specific HTTP client settings from
// environment variables. Standard HTTP_PROXY, HTTPS_PROXY, and NO_PROXY are
// still honored by NewHTTPClient when Bomly-specific values are absent.
func HTTPClientConfigFromEnv() HTTPClientConfig {
	port, _ := strconv.Atoi(strings.TrimSpace(os.Getenv(EnvHTTPProxyPort)))
	return HTTPClientConfig{
		ProxyURL:      strings.TrimSpace(os.Getenv(EnvHTTPProxy)),
		NoProxy:       strings.TrimSpace(os.Getenv(EnvHTTPNoProxy)),
		ProxyType:     strings.TrimSpace(os.Getenv(EnvHTTPProxyType)),
		ProxyHost:     strings.TrimSpace(os.Getenv(EnvHTTPProxyHost)),
		ProxyPort:     port,
		ProxyUsername: strings.TrimSpace(os.Getenv(EnvHTTPProxyUsername)),
		ProxyPassword: os.Getenv(EnvHTTPProxyPassword),
		CACertFile:    strings.TrimSpace(os.Getenv(EnvHTTPCACertFile)),
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
	if strings.TrimSpace(config.CACertFile) != "" {
		tlsConfig, err := tlsConfigWithCACert(config.CACertFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}
	return &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}, nil
}

func proxyFunc(config HTTPClientConfig) (func(*http.Request) (*url.URL, error), error) {
	proxyURL, err := resolvedProxyURL(config)
	if err != nil {
		return nil, err
	}
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

// EffectiveProxyURL returns the effective proxy URL after applying Bomly's URL or
// decomposed proxy settings. It does not inspect standard proxy environment
// variables.
func (config HTTPClientConfig) EffectiveProxyURL() (string, error) {
	return resolvedProxyURL(config)
}

func resolvedProxyURL(config HTTPClientConfig) (string, error) {
	if proxyURL := strings.TrimSpace(config.ProxyURL); proxyURL != "" {
		if err := validateProxyURL(proxyURL); err != nil {
			return "", err
		}
		return proxyURL, nil
	}
	if strings.TrimSpace(config.ProxyHost) == "" {
		return "", nil
	}
	if config.ProxyPort <= 0 || config.ProxyPort > 65535 {
		return "", fmt.Errorf("proxy port must be between 1 and 65535")
	}
	scheme, err := proxyScheme(config.ProxyType)
	if err != nil {
		return "", err
	}
	parsed := &url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(strings.TrimSpace(config.ProxyHost), strconv.Itoa(config.ProxyPort)),
	}
	username := strings.TrimSpace(config.ProxyUsername)
	if username != "" {
		if config.ProxyPassword != "" {
			parsed.User = url.UserPassword(username, config.ProxyPassword)
		} else {
			parsed.User = url.User(username)
		}
	}
	return parsed.String(), nil
}

func proxyScheme(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "http":
		return "http", nil
	case "https":
		return "https", nil
	case "socks", "socks5":
		return "socks5", nil
	default:
		return "", fmt.Errorf("proxy type %q is unsupported (accepted: http, https, socks5)", value)
	}
}

func validateProxyURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("parse proxy URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("proxy URL must be absolute")
	}
	if _, err := proxyScheme(parsed.Scheme); err != nil {
		return err
	}
	return nil
}

func tlsConfigWithCACert(path string) (*tls.Config, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("read HTTP CA certificate file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("HTTP CA certificate file does not contain any PEM certificates")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
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
