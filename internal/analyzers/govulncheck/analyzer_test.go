package govulncheck

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

func (f *fakeRunner) Run(_ context.Context, moduleDir string) (RunnerResult, error) {
	f.called++
	f.last = moduleDir
	return f.result, f.err
}

func newGoModuleDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// newGoGraph builds a single-Go-dependency graph plus a registry whose package
// (keyed by the dependency's PURL) carries the supplied vulnerabilities.
func newGoGraph(moduleDir string, vulns ...model.Vulnerability) (*model.Graph, *model.PackageRegistry) {
	g := model.New()
	dep := model.NewDependency(model.Dependency{
		Name:        "example.com/lib",
		Version:     "v1.0.0",
		Ecosystem:   "go",
		BuildSystem: "gomod",
		Locations:   []model.PackageLocation{{RealPath: filepath.Join(moduleDir, "go.sum")}},
	})
	purl := model.CanonicalPackageURLFromDependency(dep)
	dep.PackageRef = purl
	_ = g.AddNode(dep)

	registry := model.NewPackageRegistry()
	pkg := registry.Ensure(purl)
	pkg.Vulnerabilities = append(pkg.Vulnerabilities, vulns...)
	return g, registry
}

// firstVulnReachability returns the reachability for the single registry
// package's first vulnerability.
func firstVulnReachability(t *testing.T, registry *model.PackageRegistry) *model.Reachability {
	t.Helper()
	pkgs := registry.All()
	if len(pkgs) == 0 || len(pkgs[0].Vulnerabilities) == 0 {
		t.Fatal("expected a registry package with a vulnerability")
	}
	return pkgs[0].Vulnerabilities[0].Reachability
}

func TestAnalyzerMarksReachableFromGovulncheckHit(t *testing.T) {
	moduleDir := newGoModuleDir(t)
	vuln := model.Vulnerability{ID: "GO-2024-1", Source: "osv", ParsedSeverity: "high"}
	g, registry := newGoGraph(moduleDir, vuln)

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			Findings: map[string]Finding{
				"GO-2024-1": {
					OSV:        "GO-2024-1",
					CalledBy:   true,
					ImportedBy: true,
					Symbols:    []model.AffectedSymbol{{Symbol: "Decode", Package: "example.com/lib"}},
					CallPaths: []model.CallPath{
						{Frames: []model.CallFrame{
							{Function: "main", Package: "main", Position: model.SourcePosition{File: "main.go", Line: 10}},
						}},
					},
				},
			},
		},
	}}

	res, err := a.Analyze(context.Background(), model.AnalyzeRequest{
		Graph:       g,
		Registry:    registry,
		ProjectPath: moduleDir,
	})
	if err != nil {
		t.Fatalf("Analyze err: %v", err)
	}
	r := firstVulnReachability(t, registry)
	if r == nil {
		t.Fatal("expected Reachability to be set")
	}
	if r.Status != model.ReachabilityReachable {
		t.Errorf("status = %q, want reachable", r.Status)
	}
	if r.Tier != model.TierSymbol {
		t.Errorf("tier = %q, want symbol", r.Tier)
	}
	if len(r.CallPaths) != 1 {
		t.Errorf("expected 1 call path, got %d", len(r.CallPaths))
	}
	if res.AnalyzerStats[Name].Reachable != 1 {
		t.Errorf("stats.Reachable = %d, want 1", res.AnalyzerStats[Name].Reachable)
	}
}

func TestAnalyzerMarksUnreachableWhenImportedButNotCalled(t *testing.T) {
	moduleDir := newGoModuleDir(t)
	vuln := model.Vulnerability{ID: "GO-2024-2", Source: "osv", ParsedSeverity: "high"}
	g, registry := newGoGraph(moduleDir, vuln)

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			Findings: map[string]Finding{
				"GO-2024-2": {OSV: "GO-2024-2", ImportedBy: true, CalledBy: false},
			},
		},
	}}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry, ProjectPath: moduleDir})
	if err != nil {
		t.Fatal(err)
	}
	r := firstVulnReachability(t, registry)
	if r.Status != model.ReachabilityUnreachable || r.Tier != model.TierSymbol || r.Reason != "no-call-into-vulnerable-symbol" {
		t.Errorf("unexpected reachability: %+v", r)
	}
}

func TestAnalyzerMarksUnreachableTierPackageWhenModuleNotImported(t *testing.T) {
	moduleDir := newGoModuleDir(t)
	vuln := model.Vulnerability{ID: "GO-2024-3", Source: "osv", ParsedSeverity: "high"}
	g, registry := newGoGraph(moduleDir, vuln)

	// Runner returns nothing — no findings, no imported modules.
	a := Analyzer{Runner: &fakeRunner{result: RunnerResult{}}}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry, ProjectPath: moduleDir})
	if err != nil {
		t.Fatal(err)
	}
	r := firstVulnReachability(t, registry)
	if r.Status != model.ReachabilityUnreachable || r.Tier != model.TierPackage || r.Reason != "package-not-imported" {
		t.Errorf("unexpected reachability: %+v", r)
	}
}

func TestAnalyzerDegradesToUnknownOnRunnerError(t *testing.T) {
	moduleDir := newGoModuleDir(t)
	vuln := model.Vulnerability{ID: "GO-2024-4", Source: "osv", ParsedSeverity: "high"}
	g, registry := newGoGraph(moduleDir, vuln)

	a := Analyzer{Runner: &fakeRunner{err: errors.New("govulncheck binary not found")}}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry, ProjectPath: moduleDir})
	if err != nil {
		t.Fatalf("Analyze should not error on runner failure: %v", err)
	}
	r := firstVulnReachability(t, registry)
	if r.Status != model.ReachabilityUnknown {
		t.Errorf("status = %q, want unknown", r.Status)
	}
	if r.Reason != "missing-toolchain" {
		t.Errorf("reason = %q, want missing-toolchain", r.Reason)
	}
}

func TestAnalyzerBridgesCVEToGOIDViaAliases(t *testing.T) {
	moduleDir := newGoModuleDir(t)
	// Grype-style vuln carries a CVE id with an alias to the GO id.
	vuln := model.Vulnerability{
		ID:             "CVE-2024-39999",
		Source:         "grype",
		ParsedSeverity: "high",
		Aliases:        []string{"GO-2024-5", "GHSA-aaaa-bbbb-cccc"},
	}
	g, registry := newGoGraph(moduleDir, vuln)

	a := Analyzer{Runner: &fakeRunner{
		result: RunnerResult{
			Findings: map[string]Finding{
				"GO-2024-5": {
					OSV:        "GO-2024-5",
					CalledBy:   true,
					ImportedBy: true,
					Symbols:    []model.AffectedSymbol{{Symbol: "X"}},
					CallPaths:  []model.CallPath{{Frames: []model.CallFrame{{Function: "main"}}}},
					Aliases:    []string{"CVE-2024-39999"},
				},
			},
		},
	}}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry, ProjectPath: moduleDir})
	if err != nil {
		t.Fatal(err)
	}
	r := firstVulnReachability(t, registry)
	if r == nil || r.Status != model.ReachabilityReachable {
		t.Errorf("alias-bridged vuln not marked reachable: %+v", r)
	}
}

func TestAnalyzerApplicableRequiresGoVulns(t *testing.T) {
	a := Analyzer{}

	// build a graph+registry where dep's package carries the given vulns.
	build := func(name, ecosystem string, vulns ...model.Vulnerability) (*model.Graph, *model.PackageRegistry) {
		g := model.New()
		dep := model.NewDependency(model.Dependency{Name: name, Ecosystem: ecosystem})
		purl := model.CanonicalPackageURLFromDependency(dep)
		dep.PackageRef = purl
		_ = g.AddNode(dep)
		registry := model.NewPackageRegistry()
		registry.Ensure(purl).Vulnerabilities = append([]model.Vulnerability(nil), vulns...)
		return g, registry
	}

	g, registry := build("left-pad", "npm", model.Vulnerability{ID: "x"})
	if ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry}); err != nil || ok {
		t.Errorf("Applicable on npm-only graph = (%v, %v); want (false, nil)", ok, err)
	}

	g, registry = build("lib", "go", model.Vulnerability{ID: "x"})
	if ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry}); err != nil || !ok {
		t.Errorf("Applicable on go-with-vulns graph = (%v, %v); want (true, nil)", ok, err)
	}

	g, registry = build("lib", "go")
	if ok, err := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry}); err != nil || ok {
		t.Errorf("Applicable on go-without-vulns graph = (%v, %v); want (false, nil)", ok, err)
	}
}
