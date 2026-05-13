package jvmreach

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
		t.Fatal("newResultCache returned nil")
	}
	projectDir := newJVMProjectDir(t)
	want := RunnerResult{
		ImportedArtifacts: map[string]struct{}{"com.fasterxml.jackson.core:jackson-databind": {}},
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
}

func TestResultCacheInvalidatesOnBuildFileChange(t *testing.T) {
	dir := t.TempDir()
	cache := newResultCache(dir, 0)
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
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newJVMGraph(t, projectDir, "com.fasterxml.jackson.core", "jackson-databind", vuln)
	runner := &fakeRunner{
		result: RunnerResult{
			ImportedArtifacts: map[string]struct{}{"com.fasterxml.jackson.core:jackson-databind": {}},
			SourceFiles:       1,
		},
	}
	a := Analyzer{Runner: runner, CacheDir: t.TempDir()}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	if runner.called != 1 {
		t.Fatalf("first Analyze should call runner once, got %d", runner.called)
	}
	g2 := newJVMGraph(t, projectDir, "com.fasterxml.jackson.core", "jackson-databind", vuln)
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
