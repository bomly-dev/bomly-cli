package jsreach

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

	projectDir := newNPMProjectDir(t)
	want := RunnerResult{
		ImportedPackages: map[string]struct{}{"react": {}, "@scope/pkg": {}},
		EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
		SourceFiles:      4,
	}
	if err := cache.set(projectDir, "fake", "1.0", want); err != nil {
		t.Fatalf("cache.set: %v", err)
	}
	got, ok := cache.get(projectDir, "fake", "1.0")
	if !ok {
		t.Fatal("cache.get reported miss right after set")
	}
	if len(got.ImportedPackages) != 2 {
		t.Errorf("imports = %v, want 2 entries", got.ImportedPackages)
	}
	if got.SourceFiles != 4 {
		t.Errorf("source files = %d, want 4", got.SourceFiles)
	}
	if _, ok := got.ImportedPackages["react"]; !ok {
		t.Errorf("missing react in cached imports: %+v", got.ImportedPackages)
	}
}

func TestResultCacheIsolatesByRunnerName(t *testing.T) {
	dir := t.TempDir()
	cache := newResultCache(dir, 0)
	projectDir := newNPMProjectDir(t)

	if err := cache.set(projectDir, "builtin", "1.0", RunnerResult{ImportedPackages: map[string]struct{}{"a": {}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.get(projectDir, "external", "1.0"); ok {
		t.Errorf("cache lookup should miss when runner name differs")
	}
}

func TestResultCacheIsolatesByRunnerVersion(t *testing.T) {
	dir := t.TempDir()
	cache := newResultCache(dir, 0)
	projectDir := newNPMProjectDir(t)

	if err := cache.set(projectDir, "builtin", "1.0", RunnerResult{ImportedPackages: map[string]struct{}{"a": {}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.get(projectDir, "builtin", "2.0"); ok {
		t.Errorf("cache lookup should miss when runner version differs")
	}
}

func TestResultCacheInvalidatesOnLockfileChange(t *testing.T) {
	dir := t.TempDir()
	cache := newResultCache(dir, 0)
	projectDir := newNPMProjectDir(t)

	// Seed package-lock.json so checksum is stable across writes.
	lockfile := filepath.Join(projectDir, "package-lock.json")
	if err := os.WriteFile(lockfile, []byte(`{"name":"x","lockfileVersion":3,"requires":true,"packages":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cache.set(projectDir, "fake", "1.0", RunnerResult{ImportedPackages: map[string]struct{}{"a": {}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.get(projectDir, "fake", "1.0"); !ok {
		t.Fatal("cache.get reported miss right after set with lockfile present")
	}

	// Mutate the lockfile — should invalidate.
	if err := os.WriteFile(lockfile, []byte(`{"name":"x","lockfileVersion":3,"requires":true,"packages":{"react":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.get(projectDir, "fake", "1.0"); ok {
		t.Errorf("cache should miss after package-lock.json content change")
	}
}

func TestAnalyzerWithCacheServesSecondCallFromCache(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	// Ensure a lockfile exists so the cache can derive a checksum.
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newNPMGraph(t, projectDir, "react", vuln)

	runner := &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{"react": {}},
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}
	a := Analyzer{Runner: runner, CacheDir: t.TempDir()}

	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	if runner.called != 1 {
		t.Fatalf("first Analyze should call runner once, got %d", runner.called)
	}

	// Re-run with a fresh graph — runner should not be invoked.
	g2 := newNPMGraph(t, projectDir, "react", vuln)
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g2, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	if runner.called != 1 {
		t.Errorf("second Analyze should hit cache; runner.called = %d, want 1", runner.called)
	}
	r := g2.Packages()[0].Vulnerabilities[0].Reachability
	if r == nil || r.Status != model.ReachabilityReachable {
		t.Errorf("cached path did not produce a reachable annotation: %+v", r)
	}
}

func TestAnalyzerDisableCacheAlwaysRunsRunner(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}

	runner := &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{"react": {}},
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
		},
	}
	a := Analyzer{Runner: runner, CacheDir: t.TempDir(), DisableCache: true}

	g1 := newNPMGraph(t, projectDir, "react", vuln)
	g2 := newNPMGraph(t, projectDir, "react", vuln)
	for _, g := range []*model.Graph{g1, g2} {
		if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir}); err != nil {
			t.Fatal(err)
		}
	}
	if runner.called != 2 {
		t.Errorf("DisableCache should re-run runner per call; got %d calls", runner.called)
	}
}
