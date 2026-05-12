package qa

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseCaseNames(t *testing.T) {
	got := ParseCaseNames(" scan-gradle,scan-npm, scan-gradle,, ")
	want := []string{"scan-gradle", "scan-npm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCaseNames() = %#v, want %#v", got, want)
	}
	if got := ParseCaseNames("  "); got != nil {
		t.Fatalf("parseCaseNames(empty) = %#v, want nil", got)
	}
}

func TestParseSourceNames(t *testing.T) {
	got := ParseSourceNames(" github,syft-cyclonedx, github,, ")
	want := []string{"github", "syft-cyclonedx"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseSourceNames() = %#v, want %#v", got, want)
	}
}
func TestFilterScanTargets(t *testing.T) {
	targets := []ScanTarget{
		{Name: "scan-go"},
		{Name: "scan-gradle"},
		{Name: "scan-npm"},
	}
	filtered, err := filterScanTargets(targets, []string{"scan-gradle", "scan-go"})
	if err != nil {
		t.Fatalf("filterScanTargets() error = %v", err)
	}
	got := []string{filtered[0].Name, filtered[1].Name}
	want := []string{"scan-gradle", "scan-go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered names = %#v, want %#v", got, want)
	}
}

func TestFilterScanTargetsRejectsUnknownCase(t *testing.T) {
	_, err := filterScanTargets([]ScanTarget{{Name: "scan-go"}}, []string{"scan-gradle"})
	if err == nil {
		t.Fatal("expected unknown case error")
	}
	if !strings.Contains(err.Error(), "unknown or non-QA-enabled case(s): scan-gradle") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFilterBaselineSources(t *testing.T) {
	filtered, err := filterBaselineSources(defaultBaselineSources(), []string{"syft-cyclonedx", "github"})
	if err != nil {
		t.Fatalf("filterBaselineSources() error = %v", err)
	}
	got := []string{filtered[0].Name(), filtered[1].Name()}
	want := []string{"syft-cyclonedx", "github"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered source names = %#v, want %#v", got, want)
	}
	if filtered[0].BomlyFormat() != "cyclonedx-json" {
		t.Fatalf("syft-cyclonedx BomlyFormat = %q", filtered[0].BomlyFormat())
	}
}

func TestFilterBaselineSourcesRejectsUnknownSource(t *testing.T) {
	_, err := filterBaselineSources(defaultBaselineSources(), []string{"unknown"})
	if err == nil {
		t.Fatal("expected unknown source error")
	}
	if !strings.Contains(err.Error(), "unknown QA source(s): unknown") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSourceArtifactsAreGroupedBySource(t *testing.T) {
	artifacts := sourceArtifacts("syft-cyclonedx")
	if artifacts.SBOM != "sources/syft-cyclonedx/source.sbom.json" ||
		artifacts.Diff != "sources/syft-cyclonedx/diff.json" ||
		artifacts.DiffLog != "sources/syft-cyclonedx/diff.log" ||
		artifacts.Summary != "sources/syft-cyclonedx/qa-summary.json" {
		t.Fatalf("unexpected artifacts: %#v", artifacts)
	}
}

func TestRequiredBomlySBOMsAreGroupedAsSource(t *testing.T) {
	sources, err := filterBaselineSources(defaultBaselineSources(), []string{"github", "syft-cyclonedx"})
	if err != nil {
		t.Fatalf("filterBaselineSources() error = %v", err)
	}
	artifacts := requiredBomlySBOMs(sources)
	if artifacts["spdx-json"].Artifact != "sources/bomly/spdx.sbom.json" {
		t.Fatalf("spdx artifact = %q", artifacts["spdx-json"].Artifact)
	}
	if artifacts["cyclonedx-json"].Artifact != "sources/bomly/cyclonedx.sbom.json" {
		t.Fatalf("cyclonedx artifact = %q", artifacts["cyclonedx-json"].Artifact)
	}
}
func TestPrepareCasesDirPreservesUnselectedCasesForSelectedRun(t *testing.T) {
	casesDir := filepath.Join(t.TempDir(), "cases")
	writeTestFile(t, filepath.Join(casesDir, "scan-go", "qa-summary.json"), "{}")
	writeTestFile(t, filepath.Join(casesDir, "scan-gradle", "qa-summary.json"), "{}")

	err := prepareCasesDir(casesDir, []ScanTarget{{Name: "scan-gradle"}}, true)
	if err != nil {
		t.Fatalf("prepareCasesDir() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(casesDir, "scan-go", "qa-summary.json")); err != nil {
		t.Fatalf("unselected case artifact was not preserved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(casesDir, "scan-gradle")); !os.IsNotExist(err) {
		t.Fatalf("selected case dir should be removed before rerun, stat err = %v", err)
	}
}

func TestPrepareCasesDirCleansAllCasesForFullRun(t *testing.T) {
	casesDir := filepath.Join(t.TempDir(), "cases")
	writeTestFile(t, filepath.Join(casesDir, "scan-go", "qa-summary.json"), "{}")

	err := prepareCasesDir(casesDir, []ScanTarget{{Name: "scan-go"}}, false)
	if err != nil {
		t.Fatalf("prepareCasesDir() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(casesDir, "scan-go")); !os.IsNotExist(err) {
		t.Fatalf("full run should remove existing case dirs, stat err = %v", err)
	}
	if _, err := os.Stat(casesDir); err != nil {
		t.Fatalf("cases dir should be recreated: %v", err)
	}
}

func TestFetchGitHubSBOMReturnsTypedHTTPError(t *testing.T) {
	clearGitHubTokenEnv(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/bomly-dev/example-java-gradle/dependency-graph/sbom" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Used", "60")
		w.Header().Set("X-RateLimit-Reset", "1735689600")
		w.Header().Set("X-RateLimit-Resource", "core")
		w.Header().Set("Retry-After", "120")
		w.Header().Set("X-GitHub-Request-Id", "ABC:123")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found","documentation_url":"https://docs.github.com/rest/dependency-graph/sboms"}`))
	}))
	defer server.Close()

	oldBaseURL := githubAPIBaseURL
	githubAPIBaseURL = server.URL
	t.Cleanup(func() { githubAPIBaseURL = oldBaseURL })

	path := filepath.Join(t.TempDir(), "github.response.json")
	err := fetchGitHubSBOM(context.Background(), "bomly-dev/example-java-gradle", path)
	var httpErr *githubSBOMHTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected githubSBOMHTTPError, got %T: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Fatalf("StatusCode = %d, want %d", httpErr.StatusCode, http.StatusNotFound)
	}
	if httpErr.URL != server.URL+"/repos/bomly-dev/example-java-gradle/dependency-graph/sbom" {
		t.Fatalf("URL = %q", httpErr.URL)
	}
	if httpErr.OutputPath != path {
		t.Fatalf("OutputPath = %q, want %q", httpErr.OutputPath, path)
	}
	errorText := httpErr.Error()
	for _, want := range []string{
		"unauthenticated request",
		"github rate limit: limit=60 remaining=0 used=60 reset=1735689600 (2025-01-01T00:00:00Z) resource=core retry-after=120 request-id=ABC:123",
		"response body:",
		"Not Found",
	} {
		if !strings.Contains(errorText, want) {
			t.Fatalf("error does not include %q: %v", want, httpErr)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read error response: %v", err)
	}
	if string(raw) != `{"message":"Not Found","documentation_url":"https://docs.github.com/rest/dependency-graph/sboms"}` {
		t.Fatalf("unexpected error response body: %s", raw)
	}
}

func TestFetchGitHubSBOMWritesSuccessfulResponse(t *testing.T) {
	clearGitHubTokenEnv(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sbom":{"spdxVersion":"SPDX-2.3"}}`))
	}))
	defer server.Close()

	oldBaseURL := githubAPIBaseURL
	githubAPIBaseURL = server.URL
	t.Cleanup(func() { githubAPIBaseURL = oldBaseURL })

	path := filepath.Join(t.TempDir(), "github.response.json")
	if err := fetchGitHubSBOM(context.Background(), "bomly-dev/example-java-gradle", path); err != nil {
		t.Fatalf("fetchGitHubSBOM() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(raw) != `{"sbom":{"spdxVersion":"SPDX-2.3"}}` {
		t.Fatalf("unexpected response body: %s", raw)
	}
}

func TestFetchGitHubSBOMAuthenticatesWithFirstAvailableToken(t *testing.T) {
	t.Setenv("BOMLY_QA_GITHUB_TOKEN", "qa-token")
	t.Setenv("GITHUB_TOKEN", "github-token")
	t.Setenv("GH_TOKEN", "gh-token")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer qa-token" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer qa-token")
		}
		_, _ = w.Write([]byte(`{"sbom":{"spdxVersion":"SPDX-2.3"}}`))
	}))
	defer server.Close()

	oldBaseURL := githubAPIBaseURL
	githubAPIBaseURL = server.URL
	t.Cleanup(func() { githubAPIBaseURL = oldBaseURL })

	if err := fetchGitHubSBOM(context.Background(), "bomly-dev/example-java-gradle", filepath.Join(t.TempDir(), "github.response.json")); err != nil {
		t.Fatalf("fetchGitHubSBOM() error = %v", err)
	}
}

func contains(value, substring string) bool {
	return strings.Contains(value, substring)
}

func clearGitHubTokenEnv(t *testing.T) {
	t.Helper()
	for _, name := range githubTokenEnvNames {
		t.Setenv(name, "")
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create parent dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
}
