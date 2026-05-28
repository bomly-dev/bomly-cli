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

func newGraph(t *testing.T, pkgs ...*sdk.Package) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	for _, p := range pkgs {
		if err := g.AddPackage(p); err != nil {
			t.Fatalf("AddPackage: %v", err)
		}
	}
	return g
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
	pkg := &sdk.Package{ID: "scorecard@v5.0.0", Name: "scorecard", Version: "v5.0.0", PURL: "pkg:github/ossf/scorecard@v5.0.0"}
	g := newGraph(t, pkg)

	res, err := matcher.Match(context.Background(), sdk.MatchRequest{Graph: g, Mode: sdk.TargetModeFullGraph})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if res.Graph == nil {
		t.Fatal("expected graph in result")
	}
	if pkg.Scorecard == nil {
		t.Fatal("expected package to be enriched with Scorecard")
	}
	if got := pkg.Scorecard.AggregateScore; got != 8.7 {
		t.Errorf("AggregateScore = %v, want 8.7", got)
	}
	if got := pkg.Scorecard.Repository; got != "github.com/ossf/scorecard" {
		t.Errorf("Repository = %q", got)
	}
	if len(pkg.Scorecard.Checks) != 2 {
		t.Errorf("Checks = %d, want 2", len(pkg.Scorecard.Checks))
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
	pkg1 := &sdk.Package{ID: "scorecard@v5.0.0", PURL: "pkg:github/ossf/scorecard@v5.0.0", Version: "v5.0.0"}
	g1 := newGraph(t, pkg1)
	if _, err := matcher1.Match(context.Background(), sdk.MatchRequest{Graph: g1, Mode: sdk.TargetModeFullGraph}); err != nil {
		t.Fatalf("first Match: %v", err)
	}

	// Second matcher reuses the same cache dir.
	matcher2, err := New(Config{APIBase: base, CacheDir: dir})
	if err != nil {
		t.Fatalf("New2: %v", err)
	}
	pkg2 := &sdk.Package{ID: "scorecard@v5.0.0", PURL: "pkg:github/ossf/scorecard@v5.0.0", Version: "v5.0.0"}
	g2 := newGraph(t, pkg2)
	if _, err := matcher2.Match(context.Background(), sdk.MatchRequest{Graph: g2, Mode: sdk.TargetModeFullGraph}); err != nil {
		t.Fatalf("second Match: %v", err)
	}
	if pkg2.Scorecard == nil {
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
	pkg1 := &sdk.Package{ID: "x@1", PURL: "pkg:github/unscored/repo@1.0.0"}
	g1 := newGraph(t, pkg1)
	matcher, err := New(Config{APIBase: base, CacheDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := matcher.Match(context.Background(), sdk.MatchRequest{Graph: g1, Mode: sdk.TargetModeFullGraph}); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if pkg1.Scorecard != nil {
		t.Fatal("expected nil Scorecard for not-scored repo")
	}

	// Second invocation should hit the sentinel cache (no extra API call).
	pkg2 := &sdk.Package{ID: "x@1", PURL: "pkg:github/unscored/repo@1.0.0"}
	g2 := newGraph(t, pkg2)
	if _, err := matcher.Match(context.Background(), sdk.MatchRequest{Graph: g2, Mode: sdk.TargetModeFullGraph}); err != nil {
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
	pkg := &sdk.Package{ID: "x@1", PURL: "pkg:github/example/repo@1.0.0"}
	g := newGraph(t, pkg)
	if _, err := matcher.Match(context.Background(), sdk.MatchRequest{Graph: g, Mode: sdk.TargetModeFullGraph}); err != nil {
		t.Fatalf("Match must not return an error on transport failure; got %v", err)
	}
	if pkg.Scorecard != nil {
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
	pkg := &sdk.Package{ID: "x@1", PURL: "pkg:npm/internal-only@1.0.0"}
	g := newGraph(t, pkg)
	if _, err := matcher.Match(context.Background(), sdk.MatchRequest{Graph: g, Mode: sdk.TargetModeFullGraph}); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if called {
		t.Fatal("API should not be called when no github.com repo resolves")
	}
	if pkg.Scorecard != nil {
		t.Fatal("Scorecard should remain nil when no repo resolves")
	}
}

func TestMatch_ComponentModeOnlyEnrichesTarget(t *testing.T) {
	base, calls := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleResponse))
	})

	matcher := newMatcher(t, base)
	target := &sdk.Package{ID: "scorecard@v5.0.0", PURL: "pkg:github/ossf/scorecard@v5.0.0"}
	other := &sdk.Package{ID: "logrus@v1.9", PURL: "pkg:golang/github.com/sirupsen/logrus@v1.9.0"}
	g := newGraph(t, target, other)

	if _, err := matcher.Match(context.Background(), sdk.MatchRequest{
		Graph:  g,
		Target: target,
		Mode:   sdk.TargetModeComponent,
	}); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if target.Scorecard == nil {
		t.Fatal("target should be enriched")
	}
	if other.Scorecard != nil {
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
	if d.Enabled {
		t.Error("descriptor should ship Enabled=false (opt-in)")
	}
	if !matcher.Ready() {
		t.Error("Ready should be true; no runtime dependency")
	}
}
