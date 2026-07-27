package sdk

import (
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPClientRoutesRequestsThroughExplicitProxy(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests.Add(1)
		if r.URL.Host != "packages.example.test" {
			t.Errorf("proxy request host = %q, want packages.example.test", r.URL.Host)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()

	client, err := NewHTTPClient(HTTPClientConfig{ProxyURL: proxy.URL})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	resp, err := client.Get("http://packages.example.test/advisories")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	_ = resp.Body.Close()
	if proxyRequests.Load() != 1 {
		t.Fatalf("proxy requests = %d, want 1", proxyRequests.Load())
	}
}

func TestHTTPClientBypassesExplicitProxyForNoProxyDestination(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyRequests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()

	client, err := NewHTTPClient(HTTPClientConfig{
		ProxyURL: proxy.URL,
		NoProxy:  ".internal.test",
	})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	transport := client.Transport.(*http.Transport)
	destinationAddress := strings.TrimPrefix(destination.URL, "http://")
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, destinationAddress)
	}

	resp, err := client.Get("http://advisories.internal.test/v1/query")
	if err != nil {
		t.Fatalf("GET with proxy bypass: %v", err)
	}
	_ = resp.Body.Close()
	if proxyRequests.Load() != 0 {
		t.Fatalf("proxy requests = %d, want 0", proxyRequests.Load())
	}
	if destinationRequests.Load() != 1 {
		t.Fatalf("destination requests = %d, want 1", destinationRequests.Load())
	}
}

func TestHTTPClientNoProxyMatchesHostsAndNetworks(t *testing.T) {
	client, err := NewHTTPClient(HTTPClientConfig{
		ProxyURL: "http://proxy.example.test:8080",
		NoProxy:  "api.internal.test,.corp.test,10.0.0.0/8,192.0.2.10",
	})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}

	tests := []struct {
		name       string
		requestURL string
		wantProxy  bool
	}{
		{name: "exact host", requestURL: "https://api.internal.test/v1", wantProxy: false},
		{name: "domain suffix", requestURL: "https://packages.corp.test/v1", wantProxy: false},
		{name: "CIDR", requestURL: "https://10.20.30.40/v1", wantProxy: false},
		{name: "IP address", requestURL: "https://192.0.2.10/v1", wantProxy: false},
		{name: "other host", requestURL: "https://public.example.test/v1", wantProxy: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxyURL := proxyForRequest(t, client, tt.requestURL)
			if tt.wantProxy && proxyURL == nil {
				t.Fatal("proxy = nil, want configured proxy")
			}
			if !tt.wantProxy && proxyURL != nil {
				t.Fatalf("proxy = %v, want direct connection", proxyURL)
			}
		})
	}
}

func TestHTTPClientTrustsConfiguredAdditionalCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	certificate := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	certificatePath := filepath.Join(t.TempDir(), "private-ca.pem")
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatalf("write CA certificate: %v", err)
	}

	client, err := NewHTTPClient(HTTPClientConfig{
		ProxyURL:   "http://unused-proxy.invalid",
		NoProxy:    "*",
		CACertFile: certificatePath,
	})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("GET with additional CA: %v", err)
	}
	_ = resp.Body.Close()
}

func TestHTTPClientFollowsRedirectToPrivateDestinationWithoutForwardingCredentials(t *testing.T) {
	var redirectedAuthorization string
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	privateDestination := strings.Replace(destination.URL, "127.0.0.1", "localhost", 1)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "agent" || password != "redirect-secret" {
			t.Errorf("origin credentials = %q/%q/%t", username, password, ok)
		}
		http.Redirect(w, r, privateDestination+"/advisories", http.StatusFound)
	}))
	defer origin.Close()

	client, err := NewHTTPClient(HTTPClientConfig{
		ProxyURL: "http://unused-proxy.invalid",
		NoProxy:  "*",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	endpoint := strings.Replace(origin.URL, "http://", "http://agent:redirect-secret@", 1)
	resp, err := client.Get(endpoint)
	if err != nil {
		t.Fatalf("GET redirected endpoint: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if redirectedAuthorization != "" {
		t.Fatalf("redirected Authorization header = %q, want empty", redirectedAuthorization)
	}
}

func TestHTTPClientPreservesCredentialsOnSameHostRedirect(t *testing.T) {
	var redirectedAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			username, password, ok := r.BasicAuth()
			if !ok || username != "agent" || password != "redirect-secret" {
				t.Errorf("origin credentials = %q/%q/%t", username, password, ok)
			}
			http.Redirect(w, r, "/advisories", http.StatusFound)
		case "/advisories":
			redirectedAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewHTTPClient(HTTPClientConfig{
		ProxyURL: "http://unused-proxy.invalid",
		NoProxy:  "*",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	endpoint := strings.Replace(server.URL, "http://", "http://agent:redirect-secret@", 1) + "/start"
	resp, err := client.Get(endpoint)
	if err != nil {
		t.Fatalf("GET redirected endpoint: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if redirectedAuthorization == "" {
		t.Fatal("redirected Authorization header is empty, want same-host credentials")
	}
}

func TestHTTPClientTransportErrorDoesNotExposeEndpointPassword(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	client, err := NewHTTPClient(HTTPClientConfig{
		ProxyURL: "http://unused-proxy.invalid",
		NoProxy:  "*",
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	_, err = client.Get("http://agent:endpoint-secret@" + address)
	if err == nil {
		t.Fatal("GET error = nil, want connection error")
	}
	if strings.Contains(err.Error(), "endpoint-secret") {
		t.Fatalf("transport error exposed endpoint password: %q", err)
	}
}
