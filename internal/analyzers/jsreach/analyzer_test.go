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
// project (package.json + index.js).
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

// addNPMDep adds an npm dependency node to g and, when vulns are supplied,
// a matching registry package (keyed by the dependency PURL) carrying them.
// Returns the dependency node.
func addNPMDep(t *testing.T, g *model.Graph, reg *model.PackageRegistry, projectDir, org, name, version string, vulns ...model.Vulnerability) *model.Dependency {
	t.Helper()
	dep := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: name,
		Org:            org,
		Version:        version,
		Ecosystem:      model.EcosystemNPM,
		PackageManager: model.PackageManagerNPM}, Locations: []model.PackageLocation{{RealPath: filepath.Join(projectDir, "package-lock.json")}},
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

func newSeed() (*model.Graph, *model.PackageRegistry) {
	return model.New(), model.NewPackageRegistry()
}

func TestAnalyzerMarksReachableWhenPackageIsImported(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	g, reg := newSeed()
	dep := addNPMDep(t, g, reg, projectDir, "", "lodash", "1.0.0", model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{"lodash": {}, "react": {}},
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}}

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
	projectDir := newNPMProjectDir(t)
	g, reg := newSeed()
	dep := addNPMDep(t, g, reg, projectDir, "", "left-pad", "1.0.0", model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{"react": {}},
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}}

	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	r := reachOf(t, reg, dep)
	if r.Status != model.ReachabilityUnreachable || r.Tier != model.TierPackage || r.Reason != "package-not-imported" {
		t.Errorf("unexpected reachability: %+v", r)
	}
}

func TestAnalyzerDegradesToUnknownOnRunnerError(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	g, reg := newSeed()
	dep := addNPMDep(t, g, reg, projectDir, "", "lodash", "1.0.0", model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

	a := Analyzer{Runner: &fakeRunner{err: errors.New("jsreach external runner is not implemented")}}
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

func TestAnalyzerScopedPackageMatching(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	g, reg := newSeed()
	dep := addNPMDep(t, g, reg, projectDir, "@scope", "scope/pkg", "1.0.0", model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{dep.QualifiedName(): {}}, // QualifiedName
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	r := reachOf(t, reg, dep)
	if r == nil || r.Status != model.ReachabilityReachable {
		t.Errorf("scoped package not reached: %+v", r)
	}
}

func TestAnalyzerApplicableRequiresNPMVulns(t *testing.T) {
	a := Analyzer{}

	// go package with vuln → not applicable
	g, reg := newSeed()
	goDep := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "lib", Ecosystem: model.EcosystemGo}})
	goDep.PackageRef = model.CanonicalPackageURLFromDependency(goDep)
	_ = g.AddNode(goDep)
	reg.Ensure(goDep.PackageRef).Vulnerabilities = []model.Vulnerability{{ID: "x"}}
	if ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg}); err != nil || ok {
		t.Errorf("Applicable on go-only graph = (%v, %v); want (false, nil)", ok, err)
	}

	g, reg = newSeed()
	addNPMDep(t, g, reg, t.TempDir(), "", "lodash", "1.0.0", model.Vulnerability{ID: "x"})
	if ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg}); err != nil || !ok {
		t.Errorf("Applicable on npm-with-vulns graph = (%v, %v); want (true, nil)", ok, err)
	}

	g, reg = newSeed()
	addNPMDep(t, g, reg, t.TempDir(), "", "lodash", "1.0.0") // no vulns
	if ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg}); err != nil || ok {
		t.Errorf("Applicable on npm-without-vulns graph = (%v, %v); want (false, nil)", ok, err)
	}
}

func TestAnalyzerMarksTransitiveDepReachable(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	g, reg := newSeed()
	express := addNPMDep(t, g, reg, projectDir, "", "express", "4.0.0", model.Vulnerability{ID: "GHSA-direct", Source: "osv", ParsedSeverity: "high"})
	bodyParser := addNPMDep(t, g, reg, projectDir, "", "body-parser", "1.0.0", model.Vulnerability{ID: "GHSA-transitive", Source: "osv", ParsedSeverity: "high"})
	if err := g.AddEdge(express.ID, bodyParser.ID); err != nil {
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
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}

	for _, dep := range []*model.Dependency{express, bodyParser} {
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
	projectDir := newNPMProjectDir(t)
	g, reg := newSeed()
	jest := addNPMDep(t, g, reg, projectDir, "", "jest", "29.0.0", model.Vulnerability{ID: "GHSA-devtool", Source: "osv", ParsedSeverity: "high"})
	glob := addNPMDep(t, g, reg, projectDir, "", "glob", "8.0.0", model.Vulnerability{ID: "GHSA-trans", Source: "osv", ParsedSeverity: "high"})
	if err := g.AddEdge(jest.ID, glob.ID); err != nil {
		t.Fatal(err)
	}

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages: map[string]struct{}{"react": {}}, // unrelated import
			EntryPoints:      []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:      1,
		},
	}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}

	for _, dep := range []*model.Dependency{jest, glob} {
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
	a := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "a", Version: "1.0.0", Ecosystem: model.EcosystemNPM}})
	b := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "b", Version: "1.0.0", Ecosystem: model.EcosystemNPM}})
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
	dir := t.TempDir() // no package.json
	g, reg := newSeed()
	dep := addNPMDep(t, g, reg, dir, "", "lodash", "1.0.0", model.Vulnerability{ID: "x"})

	a := Analyzer{Runner: &fakeRunner{}}
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

func TestAnalyzerPopulatesHopsAndConfidence(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	g, reg := newSeed()
	express := addNPMDep(t, g, reg, projectDir, "", "express", "4.0.0", model.Vulnerability{ID: "GHSA-direct", Source: "osv", ParsedSeverity: "high"})
	bodyParser := addNPMDep(t, g, reg, projectDir, "", "body-parser", "1.0.0", model.Vulnerability{ID: "GHSA-trans", Source: "osv", ParsedSeverity: "high"})
	deep1 := addNPMDep(t, g, reg, projectDir, "", "deep1", "1")
	deep2 := addNPMDep(t, g, reg, projectDir, "", "deep2", "1")
	deep3 := addNPMDep(t, g, reg, projectDir, "", "deep3", "1")
	deep4 := addNPMDep(t, g, reg, projectDir, "", "deep4", "1", model.Vulnerability{ID: "GHSA-deep", Source: "osv", ParsedSeverity: "high"})

	for from, to := range map[string]string{
		express.ID:    bodyParser.ID,
		bodyParser.ID: deep1.ID,
		deep1.ID:      deep2.ID,
		deep2.ID:      deep3.ID,
		deep3.ID:      deep4.ID,
	} {
		if err := g.AddEdge(from, to); err != nil {
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
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}

	type expect struct {
		hops       int
		confidence model.ReachabilityConfidence
	}
	cases := []struct {
		dep  *model.Dependency
		want expect
	}{
		{express, expect{0, model.ConfidenceHigh}},
		{bodyParser, expect{1, model.ConfidenceMedium}},
		{deep4, expect{5, model.ConfidenceLow}},
	}
	for _, tc := range cases {
		r := reachOf(t, reg, tc.dep)
		if r == nil || r.Status != model.ReachabilityReachable {
			t.Fatalf("%s: expected reachable, got %+v", tc.dep.Name, r)
		}
		if r.Hops == nil || *r.Hops != tc.want.hops {
			t.Errorf("%s: hops = %v, want %d", tc.dep.Name, r.Hops, tc.want.hops)
		}
		if r.Confidence != tc.want.confidence {
			t.Errorf("%s: confidence = %q, want %q", tc.dep.Name, r.Confidence, tc.want.confidence)
		}
		if r.DynamicImportsDetected {
			t.Errorf("%s: DynamicImportsDetected = true, want false", tc.dep.Name)
		}
	}
}

func TestAnalyzerHonorsRunnerDynamicImportFlag(t *testing.T) {
	projectDir := newNPMProjectDir(t)
	g, reg := newSeed()
	dep := addNPMDep(t, g, reg, projectDir, "", "lodash", "1.0.0", model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

	a := Analyzer{DisableCache: true, Runner: &fakeRunner{
		result: RunnerResult{
			ImportedPackages:       map[string]struct{}{"lodash": {}},
			EntryPoints:            []string{filepath.Join(projectDir, "index.js")},
			SourceFiles:            1,
			DynamicImportsDetected: true,
		},
	}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	r := reachOf(t, reg, dep)
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
