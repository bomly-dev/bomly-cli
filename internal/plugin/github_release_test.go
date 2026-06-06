package plugin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
	plugschema "github.com/bomly-dev/bomly-cli/sdk"
)

func TestResolveGitHubReleaseAndInstall(t *testing.T) {
	const token = "ghp_private_release_token"
	t.Setenv("BOMLY_GITHUB_TOKEN", token)

	root := t.TempDir()
	binaryName := "bomly-plugin-release"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	if err := testutil.BuildGoBinary(t, binaryPath, fakeDetectorPluginSource("acme.detector.release")); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}

	manifest := withCanonicalManifestDefaults(Manifest{
		ID:      "acme.detector.release",
		Name:    "Acme Release Detector",
		Version: "1.0.0",
		Kind:    plugschema.PluginKindDetector,
		Entrypoint: map[string]string{
			platformKey(): filepath.ToSlash(filepath.Join("bin", filepath.Base(binaryPath))),
		},
		DetectorDescriptor: &plugschema.DetectorDescriptor{
			Name:    "acme.detector.release",
			Enabled: true,
			Origin:  plugschema.ExternalOrigin,
			PackageManagerSupport: []plugschema.PackageManagerSupport{
				plugschema.Support(plugschema.PackageManagerGoMod, "go.mod"),
			},
			Capabilities: []string{"dependency-detection"},
		},
	}, "github:acme/release-detector@v1.0.0")

	archiveName := "bomly-plugin-release_" + runtime.GOOS + "_" + runtime.GOARCH + archiveSuffix()
	archiveBytes := buildPluginArchive(t, manifest, binaryPath)
	checksum := checksumForBytes(archiveBytes)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/release-detector/releases/tags/v1.0.0":
			assertGitHubAuthHeader(t, r, token)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v1.0.0",
				"assets": []map[string]any{
					{"name": archiveName, "browser_download_url": server.URL + "/download/" + archiveName},
					{"name": "SHA256SUMS", "browser_download_url": server.URL + "/download/SHA256SUMS"},
				},
			})
		case "/download/" + archiveName:
			assertGitHubAuthHeader(t, r, token)
			_, _ = w.Write(archiveBytes)
		case "/download/SHA256SUMS":
			assertGitHubAuthHeader(t, r, token)
			_, _ = w.Write([]byte(checksum[len("sha256:"):] + "  " + archiveName + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	origBase := githubReleaseAPIBase
	origClient := pluginHTTPClient
	githubReleaseAPIBase = server.URL
	pluginHTTPClient = server.Client()
	defer func() {
		githubReleaseAPIBase = origBase
		pluginHTTPClient = origClient
	}()

	result, err := Install(context.Background(), root, "github:acme/release-detector@v1.0.0", InstallOptions{})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if result.Manifest.ID != "acme.detector.release" {
		t.Fatalf("expected release plugin id, got %q", result.Manifest.ID)
	}
	if !result.ChecksumVerified {
		t.Fatalf("expected GitHub release checksum verification to succeed")
	}
	if result.ResolvedSource != server.URL+"/download/"+archiveName {
		t.Fatalf("expected resolved source to be archive download URL, got %q", result.ResolvedSource)
	}
}

func TestResolveGitHubReleaseRedactsTokenFromErrors(t *testing.T) {
	const token = "ghp_secret_error_token"
	t.Setenv("BOMLY_GITHUB_TOKEN", token)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertGitHubAuthHeader(t, r, token)
		http.Error(w, "token "+token+" is not welcome here", http.StatusForbidden)
	}))
	defer server.Close()

	origBase := githubReleaseAPIBase
	origClient := pluginHTTPClient
	githubReleaseAPIBase = server.URL
	pluginHTTPClient = server.Client()
	defer func() {
		githubReleaseAPIBase = origBase
		pluginHTTPClient = origClient
	}()

	_, err := resolveGitHubRelease(context.Background(), "github:acme/release-detector@v1.0.0")
	if err == nil {
		t.Fatal("expected resolveGitHubRelease error")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("expected error to redact GitHub token, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("expected redacted marker in error, got %q", err.Error())
	}
}

func assertGitHubAuthHeader(t *testing.T, r *http.Request, token string) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer "+token {
		t.Fatalf("expected GitHub auth header, got %q", got)
	}
}

func buildPluginArchive(t *testing.T, manifest Manifest, binaryPath string) []byte {
	t.Helper()
	if runtime.GOOS == "windows" {
		return buildPluginZip(t, manifest, binaryPath)
	}
	return buildPluginTarGz(t, manifest, binaryPath)
}

func buildPluginTarGz(t *testing.T, manifest Manifest, binaryPath string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzw := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gzw)

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	addTarBytes(t, tw, "bomly-plugin.json", manifestBytes, 0o644)

	binaryBytes, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read plugin binary: %v", err)
	}
	addTarBytes(t, tw, filepath.ToSlash(filepath.Join("bin", filepath.Base(binaryPath))), binaryBytes, 0o755)

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buffer.Bytes()
}

func buildPluginZip(t *testing.T, manifest Manifest, binaryPath string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	writeZipBytes(t, zw, "bomly-plugin.json", manifestBytes)

	binaryBytes, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read plugin binary: %v", err)
	}
	writeZipBytes(t, zw, filepath.ToSlash(filepath.Join("bin", filepath.Base(binaryPath))), binaryBytes)

	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buffer.Bytes()
}

func addTarBytes(t *testing.T, tw *tar.Writer, name string, data []byte, mode int64) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data))}); err != nil {
		t.Fatalf("write tar header %s: %v", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("write tar entry %s: %v", name, err)
	}
}

func checksumForBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeZipBytes(t *testing.T, zw *zip.Writer, name string, data []byte) {
	t.Helper()
	writer, err := zw.Create(name)
	if err != nil {
		t.Fatalf("create zip entry %s: %v", name, err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("write zip entry %s: %v", name, err)
	}
}

func archiveSuffix() string {
	if runtime.GOOS == "windows" {
		return ".zip"
	}
	return ".tar.gz"
}

func fakeDetectorPluginSource(id string) string {
	return `package main

import (
	"context"
	"path/filepath"
	schemav1 "github.com/bomly-dev/bomly-cli/sdk"
)

type detector struct{}

func (d *detector) Metadata(ctx context.Context) (*schemav1.PluginMetadata, error) {
	return &schemav1.PluginMetadata{
		ID:               "` + id + `",
		Name:             "Fake Detector",
		Version:          "1.0.0",
		Kind:             schemav1.PluginKindDetector,
		PluginAPIVersion: schemav1.PluginAPIVersion,
	}, nil
}

func (d *detector) Descriptor(ctx context.Context) (*schemav1.DetectorDescriptor, error) {
	return &schemav1.DetectorDescriptor{
		Name:           "` + id + `",
		Enabled:        true,
		Origin:         schemav1.ExternalOrigin,
		Capabilities:   []string{"dependency-detection"},
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]schemav1.PackageManagerSupport, error) {
	return []schemav1.PackageManagerSupport{schemav1.Support(schemav1.PackageManagerGoMod, "go.mod")}, nil
}

func (d *detector) Ready(context.Context, *schemav1.DetectRequest) (*schemav1.ReadyResponse, error) {
	return &schemav1.ReadyResponse{Ready: true}, nil
}

func (d *detector) Applicable(context.Context, *schemav1.DetectRequest) (*schemav1.ApplicableResponse, error) {
	return &schemav1.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(ctx context.Context, req *schemav1.DetectRequest) (*schemav1.DetectResponse, error) {
	packageNode := schemav1.NewDependencyWithID("example.com/demo@v1.0.0", schemav1.Dependency{
		Ecosystem: string(schemav1.EcosystemGo),
		Name:      "example.com/demo",
		Version:   "v1.0.0",
		PURL:      "pkg:golang/example.com/demo@v1.0.0",
	})
	graph := schemav1.New()
	if err := graph.AddNode(packageNode); err != nil {
		return nil, err
	}
	return &schemav1.DetectResponse{
		SubprojectInfo:      req.Subproject,
		RootExecutionTarget: req.ExecutionTarget,
		DetectorName:        "` + id + `",
		Origin:              schemav1.ExternalOrigin,
		Graphs: &schemav1.GraphContainer{
			Entries: []schemav1.GraphEntry{{
				Manifest: schemav1.ManifestMetadata{
					Path: filepath.Join(req.ProjectPath, "go.mod"),
					Kind: schemav1.ManifestKind("go.mod"),
				},
				Graph: graph,
			}},
		},
	}, nil
}

func main() {
	schemav1.ServeDetector(&detector{})
}
`
}
