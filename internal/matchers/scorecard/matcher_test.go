package scorecard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const sampleResponse = `{
  "date": "2026-05-01T12:00:00Z",
  "repo": {"name": "github.com/ossf/scorecard", "commit": "abc123"},
  "scorecard": {"version": "v5.0.0", "commit": "def456"},
  "score": 8.7,
  "checks": [
    {"name": "Branch-Protection", "score": 9, "reason": "branch protection enabled", "documentation": {"short": "branch protection", "url": "https://github.com/ossf/scorecard/blob/main/docs/checks.md#branch-protection"}},
    {"name": "Code-Review", "score": 8, "reason": "all changes reviewed", "documentation": {"short": "code review", "url": "https://github.com/ossf/scorecard/blob/main/docs/checks.md#code-review"}}
  ]
}`

func newServer(t *testing.T, handler http.HandlerFunc) (string, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &calls
}

func newMatcher(t *testing.T, base string) *Matcher {
	t.Helper()
	m, err := New(Config{
		APIBase:  base,
		CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func newGraph(t *testing.T, deps ...*sdk.Dependency) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	for _, d := range deps {
		if err := g.AddNode(d); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
	}
	return g
}

// scorecardOf returns the enriched scorecard for a dependency from the registry.
func scorecardOf(reg *sdk.PackageRegistry, dep *sdk.Dependency) *sdk.PackageScorecard {
	pkg, ok := reg.Get(sdk.CanonicalPackageURLFromDependency(dep))
	if !ok || pkg == nil {
		return nil
	}
	return pkg.Scorecard
}

func TestMatch_AttachesScorecardToPackages(t *testing.T) {
	base, calls := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/projects/github.com/ossf/scorecard") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleResponse))
	})

	matcher := newMatcher(t, base)
	dep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "scorecard", Version: "v5.0.0", PURL: "pkg:github/ossf/scorecard@v5.0.0"}})
	g := newGraph(t, dep)
	registry := sdk.NewPackageRegistry()

	res, err := matcher.Match(context.Background(), sdk.MatchRequest{Graph: g, Registry: registry})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if res.Registry == nil {
		t.Fatal("expected registry in result")
	}
	card := scorecardOf(registry, dep)
	if card == nil {
		t.Fatal("expected package to be enriched with Scorecard")
	}
	if got := card.AggregateScore; got != 8.7 {
		t.Errorf("AggregateScore = %v, want 8.7", got)
	}
	if got := card.Repository; got != "github.com/ossf/scorecard" {
		t.Errorf("Repository = %q", got)
	}
	if len(card.Checks) != 2 {
		t.Errorf("Checks = %d, want 2", len(card.Checks))
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("API calls = %d, want 1", got)
	}
}

func TestMatch_CacheHitSkipsAPI(t *testing.T) {
	base, calls := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleResponse))
	})

	dir := t.TempDir()
	matcher1, err := New(Config{APIBase: base, CacheDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dep1 := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:github/ossf/scorecard@v5.0.0", Version: "v5.0.0"}})
	reg1 := sdk.NewPackageRegistry()
	if _, err := matcher1.Match(context.Background(), sdk.MatchRequest{Graph: newGraph(t, dep1), Registry: reg1}); err != nil {
		t.Fatalf("first Match: %v", err)
	}

	// Second matcher reuses the same cache dir.
	matcher2, err := New(Config{APIBase: base, CacheDir: dir})
	if err != nil {
		t.Fatalf("New2: %v", err)
	}
	dep2 := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:github/ossf/scorecard@v5.0.0", Version: "v5.0.0"}})
	reg2 := sdk.NewPackageRegistry()
	if _, err := matcher2.Match(context.Background(), sdk.MatchRequest{Graph: newGraph(t, dep2), Registry: reg2}); err != nil {
		t.Fatalf("second Match: %v", err)
	}
	if scorecardOf(reg2, dep2) == nil {
		t.Fatal("expected cached scorecard attached on second run")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("API calls = %d, want 1 (second run should hit cache)", got)
	}
}

func TestMatch_NotFoundCachedAsSentinel(t *testing.T) {
	base, calls := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not scored", http.StatusNotFound)
	})

	dir := t.TempDir()
	dep1 := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:github/unscored/repo@1.0.0", Version: "1.0.0"}})
	reg1 := sdk.NewPackageRegistry()
	matcher, err := New(Config{APIBase: base, CacheDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := matcher.Match(context.Background(), sdk.MatchRequest{Graph: newGraph(t, dep1), Registry: reg1}); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if scorecardOf(reg1, dep1) != nil {
		t.Fatal("expected nil Scorecard for not-scored repo")
	}

	// Second invocation should hit the sentinel cache (no extra API call).
	dep2 := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:github/unscored/repo@1.0.0", Version: "1.0.0"}})
	reg2 := sdk.NewPackageRegistry()
	if _, err := matcher.Match(context.Background(), sdk.MatchRequest{Graph: newGraph(t, dep2), Registry: reg2}); err != nil {
		t.Fatalf("second Match: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("API calls = %d, want 1 (404 sentinel should suppress refetch)", got)
	}
}

func TestMatch_ServerErrorIsNonFatal(t *testing.T) {
	base, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	matcher := newMatcher(t, base)
	dep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:github/example/repo@1.0.0", Version: "1.0.0"}})
	reg := sdk.NewPackageRegistry()
	if _, err := matcher.Match(context.Background(), sdk.MatchRequest{Graph: newGraph(t, dep), Registry: reg}); err != nil {
		t.Fatalf("Match must not return an error on transport failure; got %v", err)
	}
	if scorecardOf(reg, dep) != nil {
		t.Fatal("Scorecard should remain nil after 5xx")
	}
}

func TestMatch_SkipsPackagesWithoutResolvableRepo(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	t.Cleanup(srv.Close)

	matcher := newMatcher(t, srv.URL)
	dep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:npm/internal-only@1.0.0", Version: "1.0.0"}})
	reg := sdk.NewPackageRegistry()
	if _, err := matcher.Match(context.Background(), sdk.MatchRequest{Graph: newGraph(t, dep), Registry: reg}); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if called {
		t.Fatal("API should not be called when no github.com repo resolves")
	}
	if scorecardOf(reg, dep) != nil {
		t.Fatal("Scorecard should remain nil when no repo resolves")
	}
}

func TestMatch_ComponentModeOnlyEnrichesTarget(t *testing.T) {
	base, calls := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleResponse))
	})

	matcher := newMatcher(t, base)
	target := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:github/ossf/scorecard@v5.0.0", Version: "v5.0.0"}})
	other := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{PURL: "pkg:golang/github.com/sirupsen/logrus@v1.9.0", Version: "v1.9.0"}})
	g := newGraph(t, target, other)
	reg := sdk.NewPackageRegistry()

	if _, err := matcher.Match(context.Background(), sdk.MatchRequest{
		Graph:    g,
		Registry: reg,
		Target:   target,
	}); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if scorecardOf(reg, target) == nil {
		t.Fatal("target should be enriched")
	}
	if scorecardOf(reg, other) != nil {
		t.Fatal("non-target package should not be enriched in component mode")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("API calls = %d, want 1 (component mode should fetch only target's repo)", got)
	}
}

func TestDescriptor_OptIn(t *testing.T) {
	matcher := newMatcher(t, "http://example.invalid")
	d := matcher.Descriptor()
	if d.Name != "scorecard" {
		t.Errorf("Name = %q", d.Name)
	}
	if !matcher.Ready() {
		t.Error("Ready should be true; no runtime dependency")
	}
}
