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

func (f *fakeRunner) Version() string { return "fake-1.0" }

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

// TestAnalyzerMarksTransitiveDepReachable is the headline correctness
// test for the closure expansion. esbuild stops at every bare
// specifier (PackagesExternal), so the runner's import set only
// contains directly-imported packages. The graph, however, captures
// the full dep tree from the lockfile. A vulnerability in a package
// reachable only through a chain of dep edges (app → express →
// body-parser) must still be reported as reachable.
func TestAnalyzerMarksTransitiveDepReachable(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	expressVuln := model.PackageVulnerability{ID: "GHSA-direct", Source: "osv", Severity: "high"}
	bodyParserVuln := model.PackageVulnerability{ID: "GHSA-transitive", Source: "osv", Severity: "high"}

	g := model.New()
	express := model.NewPackage(model.Package{
		Name:            "express",
		Version:         "4.0.0",
		Ecosystem:       "npm",
		BuildSystem:     "npm",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}},
		Vulnerabilities: []model.PackageVulnerability{expressVuln},
	})
	bodyParser := model.NewPackage(model.Package{
		Name:            "body-parser",
		Version:         "1.0.0",
		Ecosystem:       "npm",
		BuildSystem:     "npm",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}},
		Vulnerabilities: []model.PackageVulnerability{bodyParserVuln},
	})
	if err := g.AddPackage(express); err != nil {
		t.Fatal(err)
	}
	if err := g.AddPackage(bodyParser); err != nil {
		t.Fatal(err)
	}
	if err := g.AddDependency(express.ID, bodyParser.ID); err != nil {
		t.Fatal(err)
	}

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			// App source only imports express directly.
			ImportedPackages: map[string]struct{}{"express": {}},
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}}

	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir})
	if err != nil {
		t.Fatal(err)
	}

	for _, pkg := range g.Packages() {
		r := pkg.Vulnerabilities[0].Reachability
		if r == nil {
			t.Fatalf("%s: missing Reachability", pkg.Name)
		}
		if r.Status != model.ReachabilityReachable {
			t.Errorf("%s: status = %q, want reachable (express directly imported, body-parser transitively)", pkg.Name, r.Status)
		}
	}
}

// TestAnalyzerDoesNotExpandThroughUnimportedRoots ensures the closure
// only walks from the directly-imported seed set. A vulnerable
// transitive dep that is NOT reachable from any imported package
// should stay unreachable.
func TestAnalyzerDoesNotExpandThroughUnimportedRoots(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	devToolVuln := model.PackageVulnerability{ID: "GHSA-devtool", Source: "osv", Severity: "high"}
	transitiveVuln := model.PackageVulnerability{ID: "GHSA-trans", Source: "osv", Severity: "high"}

	g := model.New()
	// jest is a devDependency that the runner's app-source walk does
	// NOT find (test files aren't entry points by default).
	jest := model.NewPackage(model.Package{
		Name:            "jest",
		Version:         "29.0.0",
		Ecosystem:       "npm",
		BuildSystem:     "npm",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}},
		Vulnerabilities: []model.PackageVulnerability{devToolVuln},
	})
	// jest depends on glob; if jest isn't reachable, glob shouldn't
	// be either, even though glob is in the dep graph.
	glob := model.NewPackage(model.Package{
		Name:            "glob",
		Version:         "8.0.0",
		Ecosystem:       "npm",
		BuildSystem:     "npm",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}},
		Vulnerabilities: []model.PackageVulnerability{transitiveVuln},
	})
	if err := g.AddPackage(jest); err != nil {
		t.Fatal(err)
	}
	if err := g.AddPackage(glob); err != nil {
		t.Fatal(err)
	}
	if err := g.AddDependency(jest.ID, glob.ID); err != nil {
		t.Fatal(err)
	}

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{"react": {}}, // unrelated import
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir})
	if err != nil {
		t.Fatal(err)
	}

	for _, pkg := range g.Packages() {
		r := pkg.Vulnerabilities[0].Reachability
		if r == nil {
			t.Fatalf("%s: missing Reachability", pkg.Name)
		}
		if r.Status != model.ReachabilityUnreachable {
			t.Errorf("%s: status = %q, want unreachable (neither directly imported nor reachable from any import)", pkg.Name, r.Status)
		}
	}
}

// TestComputeReachablePackageHopsHandlesCycles guards against the
// classic BFS pitfall: a → b → a should not loop, and the hop count
// for a transitive dep should be the shortest distance.
func TestComputeReachablePackageHopsHandlesCycles(t *testing.T) {
	g := model.New()
	a := model.NewPackage(model.Package{Name: "a", Version: "1.0.0", Ecosystem: "npm"})
	b := model.NewPackage(model.Package{Name: "b", Version: "1.0.0", Ecosystem: "npm"})
	if err := g.AddPackage(a); err != nil {
		t.Fatal(err)
	}
	if err := g.AddPackage(b); err != nil {
		t.Fatal(err)
	}
	if err := g.AddDependency(a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := g.AddDependency(b.ID, a.ID); err != nil {
		t.Fatal(err)
	}

	got := computeReachablePackageHops(g, map[string]struct{}{"a": {}})
	if h, ok := got[a.ID]; !ok || h != 0 {
		t.Errorf("expected a at hop 0: got=%v ok=%v", h, ok)
	}
	if h, ok := got[b.ID]; !ok || h != 1 {
		t.Errorf("expected b at hop 1 (transitive of a): got=%v ok=%v", h, ok)
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

// TestAnalyzerPopulatesHopsAndConfidence verifies the Tier-3
// improvements added in the reachability follow-up: each reachable
// vulnerability carries the BFS hop count and a coarse confidence
// label derived from it.
func TestAnalyzerPopulatesHopsAndConfidence(t *testing.T) {
	projectDir := newNPMProjectDir(t)

	g := model.New()
	directVuln := model.PackageVulnerability{ID: "GHSA-direct", Source: "osv", Severity: "high"}
	transitiveVuln := model.PackageVulnerability{ID: "GHSA-trans", Source: "osv", Severity: "high"}
	deepVuln := model.PackageVulnerability{ID: "GHSA-deep", Source: "osv", Severity: "high"}

	express := model.NewPackage(model.Package{
		Name:            "express",
		Version:         "4.0.0",
		Ecosystem:       "npm",
		BuildSystem:     "npm",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}},
		Vulnerabilities: []model.PackageVulnerability{directVuln},
	})
	bodyParser := model.NewPackage(model.Package{
		Name:            "body-parser",
		Version:         "1.0.0",
		Ecosystem:       "npm",
		BuildSystem:     "npm",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}},
		Vulnerabilities: []model.PackageVulnerability{transitiveVuln},
	})
	// 5 hops deep — should land at low confidence even without
	// dynamic imports.
	deep1 := model.NewPackage(model.Package{Name: "deep1", Version: "1", Ecosystem: "npm", Locations: []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}}})
	deep2 := model.NewPackage(model.Package{Name: "deep2", Version: "1", Ecosystem: "npm", Locations: []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}}})
	deep3 := model.NewPackage(model.Package{Name: "deep3", Version: "1", Ecosystem: "npm", Locations: []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}}})
	deep4 := model.NewPackage(model.Package{
		Name:            "deep4",
		Version:         "1",
		Ecosystem:       "npm",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}},
		Vulnerabilities: []model.PackageVulnerability{deepVuln},
	})

	for _, pkg := range []*model.Package{express, bodyParser, deep1, deep2, deep3, deep4} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.AddDependency(express.ID, bodyParser.ID); err != nil {
		t.Fatal(err)
	}
	for from, to := range map[string]string{
		bodyParser.ID: deep1.ID,
		deep1.ID:      deep2.ID,
		deep2.ID:      deep3.ID,
		deep3.ID:      deep4.ID,
	} {
		if err := g.AddDependency(from, to); err != nil {
			t.Fatal(err)
		}
	}

	a := Analyzer{DisableCache: true, Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{"express": {}},
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}}

	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}

	type expect struct {
		hops       int
		confidence model.ReachabilityConfidence
	}
	cases := map[string]expect{
		"express@4.0.0":     {0, model.ConfidenceHigh},
		"body-parser@1.0.0": {1, model.ConfidenceMedium},
		"deep4@1":           {5, model.ConfidenceLow},
	}
	for id, want := range cases {
		pkg, _ := g.Package(id)
		if pkg == nil {
			t.Fatalf("missing pkg %s", id)
		}
		r := pkg.Vulnerabilities[0].Reachability
		if r == nil || r.Status != model.ReachabilityReachable {
			t.Fatalf("%s: expected reachable, got %+v", id, r)
		}
		if r.Hops == nil || *r.Hops != want.hops {
			t.Errorf("%s: hops = %v, want %d", id, r.Hops, want.hops)
		}
		if r.Confidence != want.confidence {
			t.Errorf("%s: confidence = %q, want %q", id, r.Confidence, want.confidence)
		}
		if r.DynamicImportsDetected {
			t.Errorf("%s: DynamicImportsDetected = true, want false (runner reported no dynamic imports)", id)
		}
	}
}

// TestAnalyzerHonorsRunnerDynamicImportFlag verifies that when the
// runner reports dynamic imports detected, every reachable vuln is
// downgraded to ConfidenceLow even when its hop count would normally
// be ConfidenceHigh / ConfidenceMedium.
func TestAnalyzerHonorsRunnerDynamicImportFlag(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newNPMGraph(t, projectDir, "lodash", vuln)

	a := Analyzer{DisableCache: true, Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages:       map[string]struct{}{"lodash": {}},
			EntryPoints:            []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:            1,
			DynamicImportsDetected: true,
		},
	}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	r := g.Packages()[0].Vulnerabilities[0].Reachability
	if r == nil || r.Status != model.ReachabilityReachable {
		t.Fatalf("expected reachable, got %+v", r)
	}
	if !r.DynamicImportsDetected {
		t.Error("DynamicImportsDetected should be true")
	}
	if r.Confidence != model.ConfidenceLow {
		t.Errorf("confidence = %q, want low when dynamic imports detected", r.Confidence)
	}
}
