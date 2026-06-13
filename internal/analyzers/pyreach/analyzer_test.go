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
// Python project (pyproject.toml + a tiny app.py).
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

func newSeed() (*model.Graph, *model.PackageRegistry) {
	return model.New(), model.NewPackageRegistry()
}

// addPyDep adds a Python dependency node to g and (when vulns are supplied) a
// registry package keyed by the dependency PURL carrying them.
func addPyDep(t *testing.T, g *model.Graph, reg *model.PackageRegistry, projectDir, name, version string, vulns ...model.Vulnerability) *model.Dependency {
	t.Helper()
	dep := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: name,
		Version:        version,
		Ecosystem:      model.EcosystemPython,
		PackageManager: "pip"}, Locations: []model.PackageLocation{{RealPath: filepath.Join(projectDir, "requirements.txt")}},
	})
	purl := model.CanonicalPackageURLFromDependency(dep)
	dep.PackageRef = purl
	if err := g.AddNode(dep); err != nil {
		t.Fatal(err)
	}
	pkg := reg.Ensure(purl)
	pkg.Vulnerabilities = append(pkg.Vulnerabilities, vulns...)
	return dep
}

// reachOf returns the reachability for a dependency's first vulnerability.
func reachOf(t *testing.T, reg *model.PackageRegistry, dep *model.Dependency) *model.Reachability {
	t.Helper()
	pkg, ok := reg.Get(dep.PackageRef)
	if !ok || pkg == nil || len(pkg.Vulnerabilities) == 0 {
		t.Fatalf("no registry vulnerability for %s", dep.Name)
	}
	return pkg.Vulnerabilities[0].Reachability
}

func TestAnalyzerMarksReachableWhenPackageIsImported(t *testing.T) {
	projectDir := newPythonProjectDir(t)
	g, reg := newSeed()
	dep := addPyDep(t, g, reg, projectDir, "requests", "1.0.0", model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedDistributions: map[string]struct{}{"requests": {}, "flask": {}},
				SourceFiles:           1,
			},
		},
	}

	res, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Analyze err: %v", err)
	}
	r := reachOf(t, reg, dep)
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
	g, reg := newSeed()
	dep := addPyDep(t, g, reg, projectDir, "left-pad", "1.0.0", model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedDistributions: map[string]struct{}{"flask": {}},
				SourceFiles:           1,
			},
		},
	}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	r := reachOf(t, reg, dep)
	if r.Status != model.ReachabilityUnreachable || r.Tier != model.TierPackage || r.Reason != "package-not-imported" {
		t.Errorf("unexpected reachability: %+v", r)
	}
}

func TestAnalyzerDegradesToUnknownOnRunnerError(t *testing.T) {
	projectDir := newPythonProjectDir(t)
	g, reg := newSeed()
	dep := addPyDep(t, g, reg, projectDir, "requests", "1.0.0", model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

	a := Analyzer{
		DisableCache: true,
		Runner:       &fakeRunner{err: errors.New("project dir not accessible: not found")},
	}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatalf("Analyze should not error on runner failure: %v", err)
	}
	r := reachOf(t, reg, dep)
	if r.Status != model.ReachabilityUnknown {
		t.Errorf("status = %q, want unknown", r.Status)
	}
	if r.Reason != "missing-toolchain" {
		t.Errorf("reason = %q, want missing-toolchain", r.Reason)
	}
}

func TestAnalyzerNormalisesDistributionNames(t *testing.T) {
	projectDir := newPythonProjectDir(t)
	g, reg := newSeed()
	dep := addPyDep(t, g, reg, projectDir, "PyYAML", "1.0.0", model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedDistributions: map[string]struct{}{"pyyaml": {}},
				SourceFiles:           1,
			},
		},
	}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	r := reachOf(t, reg, dep)
	if r == nil || r.Status != model.ReachabilityReachable {
		t.Errorf("PyYAML / pyyaml not matched: %+v", r)
	}
}

func TestAnalyzerApplicableRequiresPythonVulns(t *testing.T) {
	a := Analyzer{}

	g, reg := newSeed()
	goDep := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "lib", Ecosystem: "go"}})
	goDep.PackageRef = model.CanonicalPackageURLFromDependency(goDep)
	_ = g.AddNode(goDep)
	reg.Ensure(goDep.PackageRef).Vulnerabilities = []model.Vulnerability{{ID: "x"}}
	if ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg}); err != nil || ok {
		t.Errorf("Applicable on go-only graph = (%v, %v); want (false, nil)", ok, err)
	}

	g, reg = newSeed()
	addPyDep(t, g, reg, t.TempDir(), "requests", "1.0.0", model.Vulnerability{ID: "x"})
	if ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg}); err != nil || !ok {
		t.Errorf("Applicable on python-with-vulns graph = (%v, %v); want (true, nil)", ok, err)
	}

	g, reg = newSeed()
	addPyDep(t, g, reg, t.TempDir(), "requests", "1.0.0") // no vulns
	if ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg}); err != nil || ok {
		t.Errorf("Applicable on python-without-vulns graph = (%v, %v); want (false, nil)", ok, err)
	}
}

func TestAnalyzerMarksTransitiveDepReachable(t *testing.T) {
	projectDir := newPythonProjectDir(t)
	g, reg := newSeed()
	requests := addPyDep(t, g, reg, projectDir, "requests", "2.32.3", model.Vulnerability{ID: "GHSA-direct", Source: "osv", ParsedSeverity: "high"})
	urllib3 := addPyDep(t, g, reg, projectDir, "urllib3", "2.2.1", model.Vulnerability{ID: "GHSA-transitive", Source: "osv", ParsedSeverity: "high"})
	if err := g.AddEdge(requests.ID, urllib3.ID); err != nil {
		t.Fatal(err)
	}

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedDistributions: map[string]struct{}{"requests": {}},
				SourceFiles:           1,
			},
		},
	}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}

	for _, dep := range []*model.Dependency{requests, urllib3} {
		r := reachOf(t, reg, dep)
		if r == nil {
			t.Fatalf("%s: missing Reachability", dep.Name)
		}
		if r.Status != model.ReachabilityReachable {
			t.Errorf("%s: status = %q, want reachable", dep.Name, r.Status)
		}
	}
}

func TestAnalyzerDoesNotExpandThroughUnimportedRoots(t *testing.T) {
	projectDir := newPythonProjectDir(t)
	g, reg := newSeed()
	pytest := addPyDep(t, g, reg, projectDir, "pytest", "8.0.0", model.Vulnerability{ID: "GHSA-devtool", Source: "osv", ParsedSeverity: "high"})
	pluggy := addPyDep(t, g, reg, projectDir, "pluggy", "1.0.0", model.Vulnerability{ID: "GHSA-trans", Source: "osv", ParsedSeverity: "high"})
	if err := g.AddEdge(pytest.ID, pluggy.ID); err != nil {
		t.Fatal(err)
	}

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedDistributions: map[string]struct{}{"flask": {}},
				SourceFiles:           1,
			},
		},
	}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	for _, dep := range []*model.Dependency{pytest, pluggy} {
		r := reachOf(t, reg, dep)
		if r == nil {
			t.Fatalf("%s: missing Reachability", dep.Name)
		}
		if r.Status != model.ReachabilityUnreachable {
			t.Errorf("%s: status = %q, want unreachable", dep.Name, r.Status)
		}
	}
}

func TestComputeReachablePackageHopsHandlesCycles(t *testing.T) {
	g := model.New()
	a := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "a", Version: "1.0.0", Ecosystem: model.EcosystemPython}})
	b := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "b", Version: "1.0.0", Ecosystem: model.EcosystemPython}})
	if err := g.AddNode(a); err != nil {
		t.Fatal(err)
	}
	if err := g.AddNode(b); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(b.ID, a.ID); err != nil {
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
	dir := t.TempDir() // no pyproject.toml
	g, reg := newSeed()
	dep := addPyDep(t, g, reg, dir, "requests", "1.0.0", model.Vulnerability{ID: "x"})

	a := Analyzer{DisableCache: true, Runner: &fakeRunner{}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: dir}); err != nil {
		t.Fatal(err)
	}
	r := reachOf(t, reg, dep)
	if r == nil || r.Status != model.ReachabilityUnknown {
		t.Errorf("expected Unknown status, got %+v", r)
	}
	if r.Reason != "no-project-root-discovered" {
		t.Errorf("reason = %q, want no-project-root-discovered", r.Reason)
	}
}
