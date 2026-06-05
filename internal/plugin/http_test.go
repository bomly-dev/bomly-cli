package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
	plugschema "github.com/bomly-dev/bomly-cli/sdk"
)

func TestInstallRemoteArchiveUsesConfiguredProxy(t *testing.T) {
	root := t.TempDir()
	binaryName := "bomly-plugin-proxy"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	if err := testutil.BuildGoBinary(t, binaryPath, fakeDetectorPluginSource("acme.detector.proxy")); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}
	manifest := withCanonicalManifestDefaults(Manifest{
		ID:      "acme.detector.proxy",
		Name:    "Acme Proxy Detector",
		Version: "1.0.0",
		Kind:    plugschema.PluginKindDetector,
		Entrypoint: map[string]string{
			platformKey(): filepath.ToSlash(filepath.Join("bin", filepath.Base(binaryPath))),
		},
		DetectorDescriptor: &plugschema.DetectorDescriptor{
			Name:    "acme.detector.proxy",
			Enabled: true,
			Origin:  plugschema.ExternalOrigin,
			PackageManagerSupport: []plugschema.PackageManagerSupport{
				plugschema.Support(plugschema.PackageManagerGoMod, "go.mod"),
			},
		},
	}, "http://plugins.example/bomly-plugin-proxy"+archiveSuffix())
	archiveBytes := buildPluginArchive(t, manifest, binaryPath)
	checksum := checksumForBytes(archiveBytes)

	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits++
		if r.URL.Host != "plugins.example" {
			t.Fatalf("proxy request host = %q", r.URL.Host)
		}
		_, _ = w.Write(archiveBytes)
	}))
	defer proxy.Close()

	ctx := WithLaunchOptions(context.Background(), LaunchOptions{HTTPProxy: proxy.URL})
	result, err := Install(ctx, root, "http://plugins.example/bomly-plugin-proxy"+archiveSuffix(), InstallOptions{Checksum: checksum})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if proxyHits == 0 {
		t.Fatalf("expected install download to use configured proxy")
	}
	if result.Manifest.ID != "acme.detector.proxy" {
		t.Fatalf("installed id = %q", result.Manifest.ID)
	}
}

func TestHTTPClientFromLaunchContextUsesSharedProvider(t *testing.T) {
	provider, err := plugschema.NewHTTPClientProvider(plugschema.HTTPClientConfig{ProxyURL: "http://proxy.example:8080"})
	if err != nil {
		t.Fatalf("NewHTTPClientProvider() error = %v", err)
	}
	ctx := WithLaunchOptions(context.Background(), LaunchOptions{HTTPClientProvider: provider})

	first, err := httpClientFromLaunchContext(ctx, 15*time.Second)
	if err != nil {
		t.Fatalf("httpClientFromLaunchContext() first error = %v", err)
	}
	second, err := httpClientFromLaunchContext(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("httpClientFromLaunchContext() second error = %v", err)
	}
	if first.Transport != second.Transport {
		t.Fatalf("plugin launch clients do not share transport")
	}
	if first.Timeout != 15*time.Second || second.Timeout != 30*time.Second {
		t.Fatalf("timeouts = %v/%v, want 15s/30s", first.Timeout, second.Timeout)
	}
}
