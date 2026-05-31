package benchmark

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseNamesDeduplicatesCommaSeparatedValues(t *testing.T) {
	got := ParseNames("github, syft", "github")
	if strings.Join(got, ",") != "github,syft" {
		t.Fatalf("ParseNames() = %#v", got)
	}
}

func TestParsePublicGitHubRepository(t *testing.T) {
	repo, err := ParsePublicGitHubRepository("https://github.com/bomly-dev/bomly-cli.git")
	if err != nil {
		t.Fatal(err)
	}
	if repo.Slug != "bomly-dev/bomly-cli" || repo.URL != "https://github.com/bomly-dev/bomly-cli" {
		t.Fatalf("repo = %#v", repo)
	}
	for _, invalid := range []string{
		"http://github.com/a/b",
		"https://gitlab.com/a/b",
		"https://token@github.com/a/b",
		"https://github.com/a/b/issues",
		"https://github.com/a/b?ref=main",
	} {
		if _, err := ParsePublicGitHubRepository(invalid); err == nil {
			t.Fatalf("ParsePublicGitHubRepository(%q) expected error", invalid)
		}
	}
}

func TestVerifyPublicGitHubRepositoryRejectsPrivateRepo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/private" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("visibility lookup sent Authorization header %q", got)
		}
		_, _ = w.Write([]byte(`{"private":true}`))
	}))
	defer server.Close()
	withGitHubAPIBase(t, server.URL)
	t.Setenv("BOMLY_BENCHMARK_GITHUB_TOKEN", "must-not-be-sent")
	err := verifyPublicGitHubRepository(context.Background(), server.Client(), PublicGitHubRepository{Slug: "acme/private"})
	if err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveTargetsValidatesCustomRepositoryFlagInteractions(t *testing.T) {
	tests := []struct {
		name string
		opts RunOptions
	}{
		{name: "case conflict", opts: RunOptions{CustomRepository: "https://github.com/acme/demo", SelectedCases: []string{"scan-npm"}}},
		{name: "ecosystem required", opts: RunOptions{CustomRepository: "https://github.com/acme/demo"}},
		{name: "install first requires repo", opts: RunOptions{InstallFirst: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := resolveTargets(context.Background(), test.opts, nil); err == nil {
				t.Fatal("resolveTargets() expected error")
			}
		})
	}
}

func TestFetchGitHubSBOMTreatsNotFoundAsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer server.Close()
	withGitHubAPIBase(t, server.URL)
	err := fetchGitHubSBOM(context.Background(), server.Client(), "acme/demo", t.TempDir()+"/response.json")
	if !isUnavailable(err) {
		t.Fatalf("error = %T %v, want unavailable", err, err)
	}
}

func TestGitHubTokenUsesBenchmarkTokenFirst(t *testing.T) {
	t.Setenv("BOMLY_BENCHMARK_GITHUB_TOKEN", "benchmark")
	t.Setenv("GITHUB_TOKEN", "github")
	t.Setenv("GH_TOKEN", "gh")
	token, name := githubTokenFromEnv()
	if token != "benchmark" || name != "BOMLY_BENCHMARK_GITHUB_TOKEN" {
		t.Fatalf("token source = %q %q", token, name)
	}
}

func TestRunRequiresNativeScanner(t *testing.T) {
	_, err := Run(context.Background(), RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "native scanner") {
		t.Fatalf("error = %v, want native scanner error", err)
	}
}

func TestUnavailableErrorMatches(t *testing.T) {
	err := &unavailableError{err: errors.New("missing")}
	if !isUnavailable(err) {
		t.Fatal("expected unavailable error")
	}
}

func withGitHubAPIBase(t *testing.T, value string) {
	t.Helper()
	previous := githubAPIBaseURL
	githubAPIBaseURL = value
	t.Cleanup(func() { githubAPIBaseURL = previous })
	for _, name := range githubTokenEnvNames {
		t.Setenv(name, "")
	}
}
