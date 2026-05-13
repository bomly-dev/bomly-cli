package jvmreach

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

type fakeRunner struct {
	result RunnerResult
	err    error
	called int
	last   string
}

func (f *fakeRunner) Name() string    { return "fake" }
func (f *fakeRunner) Version() string { return "fake-1.0" }
func (f *fakeRunner) Run(_ context.Context, projectDir string) (RunnerResult, error) {
	f.called++
	f.last = projectDir
	return f.result, f.err
}

func newJVMProjectDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pom := []byte(`<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>fixture</artifactId>
  <version>0.0.0</version>
</project>
`)
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), pom, 0o600); err != nil {
		t.Fatal(err)
	}
	srcDir := filepath.Join(dir, "src", "main", "java", "com", "example")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	app := []byte("package com.example;\nimport com.fasterxml.jackson.databind.ObjectMapper;\nclass App {}\n")
	if err := os.WriteFile(filepath.Join(srcDir, "App.java"), app, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newJVMGraph(t *testing.T, projectDir, group, artifact string, vulns ...model.PackageVulnerability) *model.Graph {
	t.Helper()
	g := model.New()
	pkg := model.NewPackage(model.Package{
		Name:            artifact,
		Org:             group,
		Version:         "1.0.0",
		Ecosystem:       string(model.EcosystemMaven),
		BuildSystem:     "maven",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "pom.xml")}},
		Vulnerabilities: vulns,
	})
	if err := g.AddPackage(pkg); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestAnalyzerMarksReachableWhenArtifactIsImported(t *testing.T) {
	projectDir := newJVMProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newJVMGraph(t, projectDir, "com.fasterxml.jackson.core", "jackson-databind", vuln)

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedArtifacts: map[string]struct{}{
					"com.fasterxml.jackson.core:jackson-databind": {},
				},
				SourceFiles: 1,
			},
		},
	}
	res, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Analyze err: %v", err)
	}
	r := res.Graph.Packages()[0].Vulnerabilities[0].Reachability
	if r == nil || r.Status != model.ReachabilityReachable || r.Tier != model.TierPackage {
		t.Errorf("unexpected reachability: %+v", r)
	}
	if res.AnalyzerStats[Name].Reachable != 1 {
		t.Errorf("stats.Reachable = %d, want 1", res.AnalyzerStats[Name].Reachable)
	}
}

func TestAnalyzerMarksUnreachableWhenArtifactNotImported(t *testing.T) {
	projectDir := newJVMProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newJVMGraph(t, projectDir, "log4j", "log4j", vuln)

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedArtifacts: map[string]struct{}{
					"com.fasterxml.jackson.core:jackson-databind": {},
				},
				SourceFiles: 1,
			},
		},
	}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir})
	if err != nil {
		t.Fatal(err)
	}
	r := g.Packages()[0].Vulnerabilities[0].Reachability
	if r.Status != model.ReachabilityUnreachable || r.Reason != "package-not-imported" {
		t.Errorf("unexpected reachability: %+v", r)
	}
}

func TestAnalyzerDegradesToUnknownOnRunnerError(t *testing.T) {
	projectDir := newJVMProjectDir(t)
	vuln := model.PackageVulnerability{ID: "GHSA-test", Source: "osv", Severity: "high"}
	g := newJVMGraph(t, projectDir, "com.fasterxml.jackson.core", "jackson-databind", vuln)

	a := Analyzer{
		DisableCache: true,
		Runner:       &fakeRunner{err: errors.New("project dir not accessible: not found")},
	}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Analyze should not error on runner failure: %v", err)
	}
	r := g.Packages()[0].Vulnerabilities[0].Reachability
	if r.Status != model.ReachabilityUnknown || r.Reason != "missing-toolchain" {
		t.Errorf("unexpected: %+v", r)
	}
}

// Transitive expansion is the headline correctness test: the
// scanner only sees direct imports, but the BFS through the dep
// graph must lift downstream artifacts to reachable too.
func TestAnalyzerMarksTransitiveDepReachable(t *testing.T) {
	projectDir := newJVMProjectDir(t)
	directVuln := model.PackageVulnerability{ID: "GHSA-direct", Source: "osv", Severity: "high"}
	transVuln := model.PackageVulnerability{ID: "GHSA-trans", Source: "osv", Severity: "high"}

	g := model.New()
	direct := model.NewPackage(model.Package{
		Name:            "jackson-databind",
		Org:             "com.fasterxml.jackson.core",
		Version:         "2.17.0",
		Ecosystem:       string(model.EcosystemMaven),
		BuildSystem:     "maven",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "pom.xml")}},
		Vulnerabilities: []model.PackageVulnerability{directVuln},
	})
	trans := model.NewPackage(model.Package{
		Name:            "jackson-core",
		Org:             "com.fasterxml.jackson.core",
		Version:         "2.17.0",
		Ecosystem:       string(model.EcosystemMaven),
		BuildSystem:     "maven",
		Locations:       []model.PackageLocation{{RealPath: filepath.Join(projectDir, "pom.xml")}},
		Vulnerabilities: []model.PackageVulnerability{transVuln},
	})
	if err := g.AddPackage(direct); err != nil {
		t.Fatal(err)
	}
	if err := g.AddPackage(trans); err != nil {
		t.Fatal(err)
	}
	if err := g.AddDependency(direct.ID, trans.ID); err != nil {
		t.Fatal(err)
	}

	a := Analyzer{
		DisableCache: true,
		Runner: &fakeRunner{
			result: RunnerResult{
				ImportedArtifacts: map[string]struct{}{
					"com.fasterxml.jackson.core:jackson-databind": {},
				},
				SourceFiles: 1,
			},
		},
	}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: projectDir})
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range g.Packages() {
		r := pkg.Vulnerabilities[0].Reachability
		if r == nil || r.Status != model.ReachabilityReachable {
			t.Errorf("%s:%s: status = %v, want reachable", pkg.Org, pkg.Name, r)
		}
	}
}

func TestComputeReachablePackageIDsHandlesCycles(t *testing.T) {
	g := model.New()
	a := model.NewPackage(model.Package{Name: "a", Org: "g", Version: "1", Ecosystem: string(model.EcosystemMaven)})
	b := model.NewPackage(model.Package{Name: "b", Org: "g", Version: "1", Ecosystem: string(model.EcosystemMaven)})
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
	got := computeReachablePackageIDs(g, map[string]struct{}{"g:a": {}})
	if _, ok := got[a.ID]; !ok {
		t.Errorf("a missing from reachable set")
	}
	if _, ok := got[b.ID]; !ok {
		t.Errorf("b missing from reachable set")
	}
}

func TestAnalyzerApplicableRequiresJVMVulns(t *testing.T) {
	a := Analyzer{}
	g := model.New()
	pyPkg := model.NewPackage(model.Package{Name: "requests", Ecosystem: string(model.EcosystemPython), Vulnerabilities: []model.PackageVulnerability{{ID: "x"}}})
	_ = g.AddPackage(pyPkg)
	ok, _ := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g})
	if ok {
		t.Errorf("Applicable on python-only graph = true; want false")
	}
	g = model.New()
	jvm := model.NewPackage(model.Package{Name: "jackson-databind", Org: "com.fasterxml.jackson.core", Ecosystem: string(model.EcosystemMaven), Vulnerabilities: []model.PackageVulnerability{{ID: "x"}}})
	_ = g.AddPackage(jvm)
	ok, _ = a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g})
	if !ok {
		t.Errorf("Applicable on jvm-with-vulns graph = false; want true")
	}
}

func TestAnalyzerMarksUnknownWhenNoProjectRootDiscovered(t *testing.T) {
	dir := t.TempDir()
	g := model.New()
	pkg := model.NewPackage(model.Package{
		Name:            "jackson-databind",
		Org:             "com.fasterxml.jackson.core",
		Ecosystem:       string(model.EcosystemMaven),
		Vulnerabilities: []model.PackageVulnerability{{ID: "x"}},
	})
	_ = g.AddPackage(pkg)
	a := Analyzer{DisableCache: true, Runner: &fakeRunner{}}
	_, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	r := g.Packages()[0].Vulnerabilities[0].Reachability
	if r == nil || r.Status != model.ReachabilityUnknown || r.Reason != "no-project-root-discovered" {
		t.Errorf("unexpected: %+v", r)
	}
}

func TestLibraryRunnerWalksProjectAndResolvesArtifacts(t *testing.T) {
	dir := t.TempDir()
	must := func(path, body string) {
		t.Helper()
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must("pom.xml", "<project></project>")
	must("src/main/java/com/example/App.java",
		"package com.example;\n"+
			"import com.fasterxml.jackson.databind.ObjectMapper;\n"+
			"import org.apache.logging.log4j.LogManager;\n"+
			"import java.util.List;\n"+
			"class App {}\n")
	// Build outputs that must be skipped:
	must("target/classes/com/decompiled/Junk.java",
		"package com.decompiled;\nimport never.seen.Class;\n")

	r := NewRunner(nil)
	got, err := r.Run(context.Background(), dir)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	expectPresent := []string{
		"com.fasterxml.jackson.core:jackson-databind",
		"org.apache.logging.log4j:log4j-api",
		"org.apache.logging.log4j:log4j-core",
	}
	for _, coord := range expectPresent {
		if _, ok := got.ImportedArtifacts[coord]; !ok {
			t.Errorf("missing %q in imported set: %v", coord, got.ImportedArtifacts)
		}
	}
	// Stdlib must not leak in.
	if _, ok := got.ImportedArtifacts["java.util:list"]; ok {
		t.Errorf("stdlib leaked into import set")
	}
	if got.SourceFiles == 0 {
		t.Error("source files = 0; want > 0")
	}
}
