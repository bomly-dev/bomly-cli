package govulncheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestResultCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cache := newResultCache(dir, 0)
	if cache == nil {
		t.Fatal("newResultCache returned nil for a writable dir")
	}

	moduleDir := newGoModuleDir(t)
	want := RunnerResult{
		Findings: map[string]Finding{
			"GO-2024-1": {OSV: "GO-2024-1", CalledBy: true, ImportedBy: true},
		},
		ImportedModules: map[string]struct{}{"example.com/lib": {}},
	}
	if err := cache.set(moduleDir, "fake", want); err != nil {
		t.Fatalf("cache.set: %v", err)
	}
	got, ok := cache.get(moduleDir, "fake")
	if !ok {
		t.Fatal("cache.get reported miss right after set")
	}
	if len(got.Findings) != 1 || got.Findings["GO-2024-1"].OSV != "GO-2024-1" {
		t.Errorf("cached findings did not round-trip: %+v", got.Findings)
	}
	if _, ok := got.ImportedModules["example.com/lib"]; !ok {
		t.Errorf("cached imported_modules did not round-trip: %+v", got.ImportedModules)
	}
}

func TestResultCacheIsolatesByRunnerName(t *testing.T) {
	dir := t.TempDir()
	cache := newResultCache(dir, 0)
	moduleDir := newGoModuleDir(t)

	if err := cache.set(moduleDir, "builtin", RunnerResult{Findings: map[string]Finding{"A": {OSV: "A"}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.get(moduleDir, "external"); ok {
		t.Errorf("cache lookup should miss when runner name differs")
	}
}

func TestResultCacheInvalidatesOnGoSumChange(t *testing.T) {
	dir := t.TempDir()
	cache := newResultCache(dir, 0)
	moduleDir := newGoModuleDir(t)

	// Seed go.sum so checksum is stable across writes.
	goSum := filepath.Join(moduleDir, "go.sum")
	if err := os.WriteFile(goSum, []byte("first content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cache.set(moduleDir, "fake", RunnerResult{Findings: map[string]Finding{"A": {OSV: "A"}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.get(moduleDir, "fake"); !ok {
		t.Fatal("cache.get reported miss right after set with go.sum present")
	}

	// Mutate go.sum — should invalidate.
	if err := os.WriteFile(goSum, []byte("second content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.get(moduleDir, "fake"); ok {
		t.Errorf("cache should miss after go.sum content change")
	}
}

func TestAnalyzerWithCacheServesSecondCallFromCache(t *testing.T) {
	moduleDir := newGoModuleDir(t)
	// Ensure go.sum exists so the cache can derive a checksum.
	if err := os.WriteFile(filepath.Join(moduleDir, "go.sum"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vuln := model.Vulnerability{ID: "GO-2024-1", Source: "osv", ParsedSeverity: "high"}
	g, registry := newGoGraph(moduleDir, vuln)

	runner := &fakeRunner{
		result: RunnerResult{
			Findings: map[string]Finding{
				"GO-2024-1": {OSV: "GO-2024-1", CalledBy: true, ImportedBy: true},
			},
		},
	}
	a := Analyzer{Runner: runner, CacheDir: t.TempDir()}

	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry, ProjectPath: moduleDir}); err != nil {
		t.Fatal(err)
	}
	if runner.called != 1 {
		t.Fatalf("first Analyze should call runner once, got %d", runner.called)
	}

	// Re-run with a fresh graph — runner should not be invoked thanks to cache.
	g2, registry2 := newGoGraph(moduleDir, vuln)
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g2, Registry: registry2, ProjectPath: moduleDir}); err != nil {
		t.Fatal(err)
	}
	if runner.called != 1 {
		t.Errorf("second Analyze should hit cache; runner.called = %d, want 1", runner.called)
	}
	r := firstVulnReachability(t, registry2)
	if r == nil || r.Status != model.ReachabilityReachable {
		t.Errorf("cached path did not produce a reachable annotation: %+v", r)
	}
}

func TestAnalyzerDisableCacheAlwaysRunsRunner(t *testing.T) {
	moduleDir := newGoModuleDir(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "go.sum"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vuln := model.Vulnerability{ID: "GO-2024-1", Source: "osv", ParsedSeverity: "high"}

	runner := &fakeRunner{
		result: RunnerResult{
			Findings: map[string]Finding{"GO-2024-1": {OSV: "GO-2024-1", CalledBy: true, ImportedBy: true}},
		},
	}
	a := Analyzer{Runner: runner, CacheDir: t.TempDir(), DisableCache: true}

	g1, registry1 := newGoGraph(moduleDir, vuln)
	g2, registry2 := newGoGraph(moduleDir, vuln)
	cases := []struct {
		g        *model.Graph
		registry *model.PackageRegistry
	}{{g1, registry1}, {g2, registry2}}
	for _, tc := range cases {
		if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: tc.g, Registry: tc.registry, ProjectPath: moduleDir}); err != nil {
			t.Fatal(err)
		}
	}
	if runner.called != 2 {
		t.Errorf("DisableCache should re-run runner per call; got %d calls", runner.called)
	}
}
