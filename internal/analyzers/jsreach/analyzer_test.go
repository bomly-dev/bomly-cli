package jsreach

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

// fakeRunner returns a canned RunnerResult or error for tests.
type fakeRunner struct {
	result RunnerResult
	err    error
	called int
	last   string
}

func (f *fakeRunner) Name() string { return "fake" }

func (f *fakeRunner) Run(_ context.Context, projectDir string) (RunnerResult, error) {
	f.called++
	f.last = projectDir
	return f.result, f.err
}

// newNPMProjectDir creates a temp directory that looks like an npm
// project (package.json + index.js). The fixture is intentionally
// minimal — most jsreach tests inject a fake runner so the actual
// esbuild walk is exercised in dedicated builtin-runner tests.
func newNPMProjectDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pkg := []byte(`{"name":"fixture","version":"0.0.0","main":"index.js"}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, "package.json"), pkg, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("module.exports = {};\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// newNPMGraph builds a single-package graph rooted at projectDir with
// the supplied vulnerabilities attached.
func newNPMGraph(t *testing.T, projectDir, name string, vulns ...model.PackageVulnerability) *model.Graph {
	t.Helper()
	g := model.New()
	pkg := model.NewPackage(model.Package{
		Name:            name,
		Version:         "1.0.0",
		Ecosystem:       "npm",
		BuildSystem:     "npm",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}},
		Vulnerabilities: vulns,
	})
	if err := g.AddPackage(pkg); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestAnalyzerMarksReachableWhenPackageIsImported(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newNPMGraph(t, projectDir, "lodash", vuln)

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{"lodash": {}, "react": {}},
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}}

	res, err := a.Analyze(context.Background(), model.AnalyzeRequest{
		Graph:       g,
		ProjectPath: projectDir,
	})
	if err != nil {
		t.Fatalf("Analyze err: %v", err)
	}
	r := res.Graph.Packages()[0].Vulnerabilities[0].Reachability
	if r == nil {
		t.Fatal("expected Reachability to be set")
	}
	if r.Status != model.ReachabilityReachable {
		t.Errorf("status = %q, want reachable", r.Status)
	}
	if r.Tier != model.TierPackage {
		t.Errorf("tier = %q, want package", r.Tier)
	}
	if res.AnalyzerStats[Name].Reachable != 1 {
		t.Errorf("stats.Reachable = %d, want 1", res.AnalyzerStats[Name].Reachable)
	}
}

func TestAnalyzerMarksUnreachableWhenPackageNotImported(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newNPMGraph(t, projectDir, "left-pad", vuln)

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{"react": {}},
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}}

	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{
		Graph:       g,
		ProjectPath: projectDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := g.Packages()[0].Vulnerabilities[0].Reachability
	if r.Status != model.ReachabilityUnreachable || r.Tier != model.TierPackage || r.Reason != "package-not-imported" {
		t.Errorf("unexpected reachability: %+v", r)
	}
}

func TestAnalyzerDegradesToUnknownOnRunnerError(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newNPMGraph(t, projectDir, "lodash", vuln)

	a := Analyzer{Runner: &fakeRunner{err: errors.New("jsreach external runner is not implemented")}}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{
		Graph:       g,
		ProjectPath: projectDir,
	})
	if err != nil {
		t.Fatalf("Analyze should not error on runner failure: %v", err)
	}
	r := g.Packages()[0].Vulnerabilities[0].Reachability
	if r.Status != model.ReachabilityUnknown {
		t.Errorf("status = %q, want unknown", r.Status)
	}
	if r.Reason != "missing-toolchain" {
		t.Errorf("reason = %q, want missing-toolchain", r.Reason)
	}
}

func TestAnalyzerScopedPackageMatching(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := model.New()
	pkg := model.NewPackage(model.Package{
		Name:        "scope/pkg",
		Org:         "@scope",
		Version:     "1.0.0",
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Locations: []model.PackageLocation{
			{RealPath: filepath.Join(projectDir, "package-lock.json")},
		},
		Vulnerabilities: []model.PackageVulnerability{vuln},
	})
	if err := g.AddPackage(pkg); err != nil {
		t.Fatal(err)
	}

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{"@scope:scope/pkg": {}}, // QualifiedName
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir})
	if err != nil {
		t.Fatal(err)
	}
	r := g.Packages()[0].Vulnerabilities[0].Reachability
	if r == nil || r.Status != model.ReachabilityReachable {
		t.Errorf("scoped package not reached: %+v", r)
	}
}

func TestAnalyzerApplicableRequiresNPMVulns(t *testing.T) {
	a := Analyzer{}

	g := model.New()
	goPkg := model.NewPackage(model.Package{Name: "lib", Ecosystem: "go", Vulnerabilities: []model.PackageVulnerability{{ID: "x"}}})
	_ = g.AddPackage(goPkg)
	ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g})
	if err != nil || ok {
		t.Errorf("Applicable on go-only graph = (%v, %v); want (false, nil)", ok, err)
	}

	g = model.New()
	npmPkg := model.NewPackage(model.Package{Name: "lodash", Ecosystem: "npm", Vulnerabilities: []model.PackageVulnerability{{ID: "x"}}})
	_ = g.AddPackage(npmPkg)
	ok, err = a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g})
	if err != nil || !ok {
		t.Errorf("Applicable on npm-with-vulns graph = (%v, %v); want (true, nil)", ok, err)
	}

	g = model.New()
	npmNoVulns := model.NewPackage(model.Package{Name: "lodash", Ecosystem: "npm"})
	_ = g.AddPackage(npmNoVulns)
	ok, err = a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g})
	if err != nil || ok {
		t.Errorf("Applicable on npm-without-vulns graph = (%v, %v); want (false, nil)", ok, err)
	}
}

func TestAnalyzerMarksUnknownWhenNoProjectRootDiscovered(t *testing.T) {
	// Project path doesn't contain a package.json — discoverProjectRoots
	// returns empty so the analyzer should mark every npm vuln Unknown.
	dir := t.TempDir()
	g := model.New()
	pkg := model.NewPackage(model.Package{
		Name:            "lodash",
		Ecosystem:       "npm",
		Vulnerabilities: []model.PackageVulnerability{{ID: "x"}},
	})
	_ = g.AddPackage(pkg)

	a := Analyzer{Runner: &fakeRunner{}}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	r := g.Packages()[0].Vulnerabilities[0].Reachability
	if r == nil || r.Status != model.ReachabilityUnknown {
		t.Errorf("expected Unknown status, got %+v", r)
	}
	if r.Reason != "no-project-root-discovered" {
		t.Errorf("reason = %q, want no-project-root-discovered", r.Reason)
	}
}
