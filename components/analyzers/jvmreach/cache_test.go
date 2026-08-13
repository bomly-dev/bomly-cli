package jvmreach

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestResultCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cache := newResultCache(dir, 0, nil)
	if cache == nil {
		t.Fatal("newResultCache returned nil")
	}
	projectDir := newJVMProjectDir(t)
	want := RunnerResult{
		ImportedArtifacts: map[string]struct{}{"com.fasterxml.jackson.core:jackson-databind": {}},
		RawImports:        map[string]struct{}{"com.fasterxml.jackson.databind.ObjectMapper": {}},
		SourceFiles:       3,
	}
	if err := cache.set(projectDir, "fake", "1.0", want); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok := cache.get(projectDir, "fake", "1.0")
	if !ok {
		t.Fatal("cache miss right after set")
	}
	if got.SourceFiles != 3 {
		t.Errorf("source files = %d, want 3", got.SourceFiles)
	}
	if _, ok := got.ImportedArtifacts["com.fasterxml.jackson.core:jackson-databind"]; !ok {
		t.Errorf("missing artifact in cached result")
	}
	if _, ok := got.RawImports["com.fasterxml.jackson.databind.ObjectMapper"]; !ok {
		t.Errorf("missing raw import in cached result")
	}
}

func TestResultCacheInvalidatesOnBuildFileChange(t *testing.T) {
	dir := t.TempDir()
	cache := newResultCache(dir, 0, nil)
	projectDir := newJVMProjectDir(t)
	pom := filepath.Join(projectDir, "pom.xml")
	if err := cache.set(projectDir, "fake", "1.0", RunnerResult{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.get(projectDir, "fake", "1.0"); !ok {
		t.Fatal("cache miss right after set")
	}
	if err := os.WriteFile(pom, []byte("<project>changed</project>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.get(projectDir, "fake", "1.0"); ok {
		t.Errorf("cache should miss after pom.xml content change")
	}
}

func TestAnalyzerWithCacheServesSecondCallFromCache(t *testing.T) {
	projectDir := newJVMProjectDir(t)
	vuln := model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"}
	g, reg := newSeed()
	addJVMDep(t, g, reg, projectDir, "com.fasterxml.jackson.core", "jackson-databind", "1.0.0", vuln)
	runner := &fakeRunner{
		result: RunnerResult{
			ImportedArtifacts: map[string]struct{}{"com.fasterxml.jackson.core:jackson-databind": {}},
			SourceFiles:       1,
		},
	}
	a := Analyzer{Runner: runner, CacheDir: t.TempDir()}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	if runner.called != 1 {
		t.Fatalf("first Analyze should call runner once, got %d", runner.called)
	}
	g2, reg2 := newSeed()
	dep2 := addJVMDep(t, g2, reg2, projectDir, "com.fasterxml.jackson.core", "jackson-databind", "1.0.0", vuln)
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g2, Registry: reg2, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	if runner.called != 1 {
		t.Errorf("second Analyze should hit cache; runner.called = %d, want 1", runner.called)
	}
	r := reachOf(t, reg2, dep2)
	if r == nil || r.Status != model.ReachabilityReachable {
		t.Errorf("cached path did not produce a reachable annotation: %+v", r)
	}
}

func TestNewResultCacheWarnsWhenInitFails(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	cache := newResultCache(filepath.Join(blocker, "nested"), 0, zap.New(core))
	if cache != nil {
		t.Fatal("expected nil cache when the cache root cannot be created")
	}
	if got := logs.FilterLevelExact(zap.WarnLevel).Len(); got != 1 {
		t.Fatalf("expected exactly one WARN log, got %d: %v", got, logs.All())
	}
}
