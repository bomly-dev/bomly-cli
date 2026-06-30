package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestInstallRemoteArchiveDoesNotUseUnsafeGitHubAssetName(t *testing.T) {
	root := t.TempDir()
	tempDir := filepath.Join(root, "install")
	if err := os.Mkdir(tempDir, 0o755); err != nil {
		t.Fatalf("create temp install dir: %v", err)
	}

	binaryName := "bomly-plugin-unsafe-name"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	if err := testutil.BuildGoBinary(t, binaryPath, fakeDetectorPluginSource("acme.detector.unsafe-name")); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}
	manifest := withCanonicalManifestDefaults(Manifest{
		ID:      "acme.detector.unsafe-name",
		Name:    "Acme Unsafe Name Detector",
		Version: "1.0.0",
		Kind:    plugschema.PluginKindDetector,
		Entrypoint: map[string]string{
			platformKey(): filepath.ToSlash(filepath.Join("bin", filepath.Base(binaryPath))),
		},
	}, "github:acme/unsafe-name@v1.0.0")
	archiveBytes := buildPluginArchive(t, manifest, binaryPath)

	escapedName := "bomly-plugin-escape" + archiveSuffix()
	escapedPath := filepath.Join(filepath.Dir(root), escapedName)
	_ = os.Remove(escapedPath)
	defer func() { _ = os.Remove(escapedPath) }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archiveBytes)
	}))
	defer server.Close()

	result, _, err := installRemoteArchive(context.Background(), tempDir, server.URL+"/asset", InstallOptions{
		InsecureSkipChecksum:   true,
		githubReleaseDownload:  true,
		githubReleaseAssetName: "../" + escapedName,
	})
	if err != nil {
		t.Fatalf("installRemoteArchive() error = %v", err)
	}
	if result.ID != "acme.detector.unsafe-name" {
		t.Fatalf("installed id = %q", result.ID)
	}
	if _, err := os.Stat(escapedPath); !os.IsNotExist(err) {
		t.Fatalf("unsafe asset name created %q", escapedPath)
	}
}

func TestInstallArchiveRejectsUnsafeManifestEntrypoint(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "install")
	if err := os.Mkdir(tempDir, 0o755); err != nil {
		t.Fatalf("create temp install dir: %v", err)
	}

	binaryName := "bomly-plugin-unsafe-entrypoint"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	if err := testutil.BuildGoBinary(t, binaryPath, fakeDetectorPluginSource("acme.detector.unsafe-entrypoint")); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}
	manifest := withCanonicalManifestDefaults(Manifest{
		ID:      "acme.detector.unsafe-entrypoint",
		Name:    "Acme Unsafe Entrypoint Detector",
		Version: "1.0.0",
		Kind:    plugschema.PluginKindDetector,
		Entrypoint: map[string]string{
			platformKey(): filepath.ToSlash(filepath.Join("..", "bin", filepath.Base(binaryPath))),
		},
	}, "file://unsafe-entrypoint")
	archiveBytes := buildPluginArchive(t, manifest, binaryPath)
	archivePath := filepath.Join(t.TempDir(), "unsafe-entrypoint"+archiveSuffix())
	if err := os.WriteFile(archivePath, archiveBytes, 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	_, _, err := installArchiveAtPath(context.Background(), tempDir, archivePath, archivePath, "", true)
	if err == nil || !strings.Contains(err.Error(), "must stay within the plugin directory") {
		t.Fatalf("expected unsafe entrypoint error, got %v", err)
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
