package benchmark

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestParseNamesDeduplicatesCommaSeparatedValues(t *testing.T) {
	got := ParseNames("github, syft", "github")
	if strings.Join(got, ",") != "github,syft" {
		t.Fatalf("ParseNames() = %#v", got)
	}
}

func TestDefaultBaselineSourceRoles(t *testing.T) {
	sources := defaultBaselineSources()
	if len(sources) != 3 || sources[0].Role() != "evidence" || sources[1].Role() != "observation" || sources[2].Role() != "observation" {
		t.Fatalf("source roles = %#v, %#v, %#v", sources[0].Role(), sources[1].Role(), sources[2].Role())
	}
	if sources[0].AgreementGroup() != "github" || sources[1].AgreementGroup() != "syft" || sources[2].AgreementGroup() != "syft" {
		t.Fatalf("agreement groups = %#v, %#v, %#v", sources[0].AgreementGroup(), sources[1].AgreementGroup(), sources[2].AgreementGroup())
	}
}

func TestBenchmarkCasesDirIsAbsolute(t *testing.T) {
	got, err := benchmarkCasesDir(filepath.Join(".benchmark-runs", "latest"))
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("benchmarkCasesDir() = %q, want absolute path", got)
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

func TestComparisonPolicyClassifiesNonRegistryGraphAndPinnedEdges(t *testing.T) {
	graph := sdk.New()
	app := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:npm/app@1.0.0", Ecosystem: sdk.EcosystemNPM, Name: "app", Version: "1.0.0", Type: sdk.PackageTypeApplication}, Source: sdk.DependencySourceProject})
	registry := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:npm/registry@1.0.0", Ecosystem: sdk.EcosystemNPM, Name: "registry", Version: "1.0.0"}, Source: sdk.DependencySourceRegistry})
	gitDependency := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:npm/git-dependency@1.0.0", Ecosystem: sdk.EcosystemNPM, Name: "git-dependency", Version: "1.0.0"}, Source: sdk.DependencySourceGit})
	for _, dependency := range []*sdk.Dependency{app, registry, gitDependency} {
		if err := graph.AddNode(dependency); err != nil {
			t.Fatal(err)
		}
	}
	for _, edge := range [][2]string{{app.ID, registry.ID}, {app.ID, gitDependency.ID}} {
		if err := graph.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatal(err)
		}
	}
	target := Target{AdjudicatedRelationships: []AdjudicatedRelationship{{From: registry.PURL, To: "pkg:npm/child@1.0.0", Reason: "pinned evidence"}}}

	policy := comparisonPolicy(graph, target)
	for _, purl := range []string{app.PURL, gitDependency.PURL} {
		if policy.PackageExtensions[sdk.CanonicalizePackageURL(purl)] == "" {
			t.Fatalf("missing package extension for %s: %#v", purl, policy.PackageExtensions)
		}
	}
	if _, ok := policy.PackageExtensions[sdk.CanonicalizePackageURL(registry.PURL)]; ok {
		t.Fatalf("registry release classified as extension: %#v", policy.PackageExtensions)
	}
	for _, edge := range []string{
		relationshipKey(sdk.CanonicalizePackageURL(app.PURL), sdk.CanonicalizePackageURL(registry.PURL)),
		relationshipKey(sdk.CanonicalizePackageURL(app.PURL), sdk.CanonicalizePackageURL(gitDependency.PURL)),
		relationshipKey(sdk.CanonicalizePackageURL(registry.PURL), "pkg:npm/child@1.0.0"),
	} {
		if policy.RelationshipExtensions[edge] == "" {
			t.Fatalf("missing relationship extension for %q: %#v", edge, policy.RelationshipExtensions)
		}
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
