package pyreach

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

// newPythonProjectDir creates a temp directory that looks like a
// Python project (pyproject.toml + a tiny app.py). The fixture is
// intentionally minimal — most pyreach tests inject a fake runner
// so the disk-walking scanner is exercised separately.
func newPythonProjectDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pyproject := []byte("[project]\nname = \"fixture\"\nversion = \"0.0.0\"\n")
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), pyproject, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// newPyGraph builds a single-package graph rooted at projectDir with
// the supplied vulnerabilities attached.
func newPyGraph(t *testing.T, projectDir, name string, vulns ...model.PackageVulnerability) *model.Graph {
	t.Helper()
	g := model.New()
	pkg := model.NewPackage(model.Package{
		Name:            name,
		Version:         "1.0.0",
		Ecosystem:       string(model.EcosystemPython),
		BuildSystem:     "pip",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "requirements.txt")}},
		Vulnerabilities: vulns,
	})
	if err := g.AddPackage(pkg); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestAnalyzerMarksReachableWhenPackageIsImported(t *testing.T) {
	projectDir := newPythonProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newPyGraph(t, projectDir, "requests", vuln)

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedDistributions: map[string]struct{}{"requests": {}, "flask": {}},
				SourceFiles:           1,
			},
		},
	}

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
	projectDir := newPythonProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newPyGraph(t, projectDir, "left-pad", vuln)

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedDistributions: map[string]struct{}{"flask": {}},
				SourceFiles:           1,
			},
		},
	}

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
	projectDir := newPythonProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newPyGraph(t, projectDir, "requests", vuln)

	a := Analyzer{
		DisableCache: true,
		Runner:       &fakeRunner{err: errors.New("project dir not accessible: not found")},
	}
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

// TestAnalyzerNormalisesDistributionNames covers the case where the
// import set is normalized but the graph package name is not — both
// sides go through canonicalDistName before comparison so PEP 503
// equivalents (PyYAML / pyyaml, my_pkg / my-pkg) match.
func TestAnalyzerNormalisesDistributionNames(t *testing.T) {
	projectDir := newPythonProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newPyGraph(t, projectDir, "PyYAML", vuln)

	// Runner emits the canonicalised "pyyaml" form (which is what
	// moduleToDistribution would produce for `import yaml`).
	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedDistributions: map[string]struct{}{"pyyaml": {}},
				SourceFiles:           1,
			},
		},
	}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir})
	if err != nil {
		t.Fatal(err)
	}
	r := g.Packages()[0].Vulnerabilities[0].Reachability
	if r == nil || r.Status != model.ReachabilityReachable {
		t.Errorf("PyYAML / pyyaml not matched: %+v", r)
	}
}

func TestAnalyzerApplicableRequiresPythonVulns(t *testing.T) {
	a := Analyzer{}

	g := model.New()
	goPkg := model.NewPackage(model.Package{Name: "lib", Ecosystem: "go", Vulnerabilities: []model.PackageVulnerability{{ID: "x"}}})
	_ = g.AddPackage(goPkg)
	ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g})
	if err != nil || ok {
		t.Errorf("Applicable on go-only graph = (%v, %v); want (false, nil)", ok, err)
	}

	g = model.New()
	pyPkg := model.NewPackage(model.Package{Name: "requests", Ecosystem: string(model.EcosystemPython), Vulnerabilities: []model.PackageVulnerability{{ID: "x"}}})
	_ = g.AddPackage(pyPkg)
	ok, err = a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g})
	if err != nil || !ok {
		t.Errorf("Applicable on python-with-vulns graph = (%v, %v); want (true, nil)", ok, err)
	}

	g = model.New()
	pyNoVulns := model.NewPackage(model.Package{Name: "requests", Ecosystem: string(model.EcosystemPython)})
	_ = g.AddPackage(pyNoVulns)
	ok, err = a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g})
	if err != nil || ok {
		t.Errorf("Applicable on python-without-vulns graph = (%v, %v); want (false, nil)", ok, err)
	}
}

// TestAnalyzerMarksTransitiveDepReachable is the headline correctness
// test for the closure expansion. The import scanner only returns
// the top-level distributions imported in app source. Transitively
// reachable distributions (urllib3 pulled in by requests) must still
// be reported as reachable.
func TestAnalyzerMarksTransitiveDepReachable(t *testing.T) {
	projectDir := newPythonProjectDir(t)
	requestsVuln := model.PackageVulnerability{ID: "GHSA-direct", Source: "osv", Severity: "high"}
	urllib3Vuln := model.PackageVulnerability{ID: "GHSA-transitive", Source: "osv", Severity: "high"}

	g := model.New()
	requests := model.NewPackage(model.Package{
		Name:            "requests",
		Version:         "2.32.3",
		Ecosystem:       string(model.EcosystemPython),
		BuildSystem:     "pip",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "requirements.txt")}},
		Vulnerabilities: []model.PackageVulnerability{requestsVuln},
	})
	urllib3 := model.NewPackage(model.Package{
		Name:            "urllib3",
		Version:         "2.2.1",
		Ecosystem:       string(model.EcosystemPython),
		BuildSystem:     "pip",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "requirements.txt")}},
		Vulnerabilities: []model.PackageVulnerability{urllib3Vuln},
	})
	if err := g.AddPackage(requests); err != nil {
		t.Fatal(err)
	}
	if err := g.AddPackage(urllib3); err != nil {
		t.Fatal(err)
	}
	if err := g.AddDependency(requests.ID, urllib3.ID); err != nil {
		t.Fatal(err)
	}

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				// App source only imports requests directly.
				ImportedDistributions: map[string]struct{}{"requests": {}},
				SourceFiles:           1,
			},
		},
	}

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
			t.Errorf("%s: status = %q, want reachable", pkg.Name, r.Status)
		}
	}
}

// TestAnalyzerDoesNotExpandThroughUnimportedRoots ensures the
// closure only walks from the directly-imported seed set. A
// vulnerable transitive dep that is NOT reachable from any imported
// distribution should stay unreachable.
func TestAnalyzerDoesNotExpandThroughUnimportedRoots(t *testing.T) {
	projectDir := newPythonProjectDir(t)
	pytestVuln := model.PackageVulnerability{ID: "GHSA-devtool", Source: "osv", Severity: "high"}
	transVuln := model.PackageVulnerability{ID: "GHSA-trans", Source: "osv", Severity: "high"}

	g := model.New()
	pytest := model.NewPackage(model.Package{
		Name:            "pytest",
		Version:         "8.0.0",
		Ecosystem:       string(model.EcosystemPython),
		BuildSystem:     "pip",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "requirements.txt")}},
		Vulnerabilities: []model.PackageVulnerability{pytestVuln},
	})
	pluggy := model.NewPackage(model.Package{
		Name:            "pluggy",
		Version:         "1.0.0",
		Ecosystem:       string(model.EcosystemPython),
		BuildSystem:     "pip",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "requirements.txt")}},
		Vulnerabilities: []model.PackageVulnerability{transVuln},
	})
	if err := g.AddPackage(pytest); err != nil {
		t.Fatal(err)
	}
	if err := g.AddPackage(pluggy); err != nil {
		t.Fatal(err)
	}
	if err := g.AddDependency(pytest.ID, pluggy.ID); err != nil {
		t.Fatal(err)
	}

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				// Unrelated import; pytest is dev-only and not seen.
				ImportedDistributions: map[string]struct{}{"flask": {}},
				SourceFiles:           1,
			},
		},
	}
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
			t.Errorf("%s: status = %q, want unreachable", pkg.Name, r.Status)
		}
	}
}

// TestComputeReachablePackageIDsHandlesCycles guards against the
// classic BFS pitfall: a → b → a should not loop.
func TestComputeReachablePackageIDsHandlesCycles(t *testing.T) {
	g := model.New()
	a := model.NewPackage(model.Package{Name: "a", Version: "1.0.0", Ecosystem: string(model.EcosystemPython)})
	b := model.NewPackage(model.Package{Name: "b", Version: "1.0.0", Ecosystem: string(model.EcosystemPython)})
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

	got := computeReachablePackageIDs(g, map[string]struct{}{"a": {}})
	if _, ok := got[a.ID]; !ok {
		t.Errorf("expected a in reachable set: %v", got)
	}
	if _, ok := got[b.ID]; !ok {
		t.Errorf("expected b (transitive of a) in reachable set: %v", got)
	}
}

func TestAnalyzerMarksUnknownWhenNoProjectRootDiscovered(t *testing.T) {
	dir := t.TempDir()
	g := model.New()
	pkg := model.NewPackage(model.Package{
		Name:            "requests",
		Ecosystem:       string(model.EcosystemPython),
		Vulnerabilities: []model.PackageVulnerability{{ID: "x"}},
	})
	_ = g.AddPackage(pkg)

	a := Analyzer{DisableCache: true, Runner: &fakeRunner{}}
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
