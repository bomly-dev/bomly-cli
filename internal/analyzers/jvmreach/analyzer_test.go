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

func newSeed() (*model.Graph, *model.PackageRegistry) {
	return model.New(), model.NewPackageRegistry()
}

// addJVMDep adds a Maven dependency node + (when vulns supplied) a registry
// package keyed by the dependency PURL carrying those vulnerabilities.
func addJVMDep(t *testing.T, g *model.Graph, reg *model.PackageRegistry, projectDir, group, artifact, version string, vulns ...model.Vulnerability) *model.Dependency {
	t.Helper()
	dep := model.NewDependency(model.Dependency{
		Name:           artifact,
		Org:            group,
		Version:        version,
		Ecosystem:      model.EcosystemMaven,
		PackageManager: "maven",
		Locations:      []model.PackageLocation{{RealPath: filepath.Join(projectDir, "pom.xml")}},
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

func reachOf(t *testing.T, reg *model.PackageRegistry, dep *model.Dependency) *model.Reachability {
	t.Helper()
	pkg, ok := reg.Get(dep.PackageRef)
	if !ok || pkg == nil || len(pkg.Vulnerabilities) == 0 {
		t.Fatalf("no registry vulnerability for %s:%s", dep.Org, dep.Name)
	}
	return pkg.Vulnerabilities[0].Reachability
}

func TestAnalyzerMarksReachableWhenArtifactIsImported(t *testing.T) {
	projectDir := newJVMProjectDir(t)
	g, reg := newSeed()
	dep := addJVMDep(t, g, reg, projectDir, "com.fasterxml.jackson.core", "jackson-databind", "1.0.0",
		model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

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
	res, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Analyze err: %v", err)
	}
	r := reachOf(t, reg, dep)
	if r == nil || r.Status != model.ReachabilityReachable || r.Tier != model.TierPackage {
		t.Errorf("unexpected reachability: %+v", r)
	}
	if res.AnalyzerStats[Name].Reachable != 1 {
		t.Errorf("stats.Reachable = %d, want 1", res.AnalyzerStats[Name].Reachable)
	}
}

func TestAnalyzerMarksUnreachableWhenArtifactNotImported(t *testing.T) {
	projectDir := newJVMProjectDir(t)
	g, reg := newSeed()
	dep := addJVMDep(t, g, reg, projectDir, "log4j", "log4j", "1.0.0",
		model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

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
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	r := reachOf(t, reg, dep)
	if r.Status != model.ReachabilityUnreachable || r.Reason != "package-not-imported" {
		t.Errorf("unexpected reachability: %+v", r)
	}
}

func TestAnalyzerDegradesToUnknownOnRunnerError(t *testing.T) {
	projectDir := newJVMProjectDir(t)
	g, reg := newSeed()
	dep := addJVMDep(t, g, reg, projectDir, "com.fasterxml.jackson.core", "jackson-databind", "1.0.0",
		model.Vulnerability{ID: "GHSA-test", Source: "osv", ParsedSeverity: "high"})

	a := Analyzer{
		DisableCache: true,
		Runner:       &fakeRunner{err: errors.New("project dir not accessible: not found")},
	}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatalf("Analyze should not error on runner failure: %v", err)
	}
	r := reachOf(t, reg, dep)
	if r.Status != model.ReachabilityUnknown || r.Reason != "missing-toolchain" {
		t.Errorf("unexpected: %+v", r)
	}
}

func TestAnalyzerMarksTransitiveDepReachable(t *testing.T) {
	projectDir := newJVMProjectDir(t)
	g, reg := newSeed()
	direct := addJVMDep(t, g, reg, projectDir, "com.fasterxml.jackson.core", "jackson-databind", "2.17.0",
		model.Vulnerability{ID: "GHSA-direct", Source: "osv", ParsedSeverity: "high"})
	trans := addJVMDep(t, g, reg, projectDir, "com.fasterxml.jackson.core", "jackson-core", "2.17.0",
		model.Vulnerability{ID: "GHSA-trans", Source: "osv", ParsedSeverity: "high"})
	if err := g.AddEdge(direct.ID, trans.ID); err != nil {
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
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: projectDir}); err != nil {
		t.Fatal(err)
	}
	for _, dep := range []*model.Dependency{direct, trans} {
		r := reachOf(t, reg, dep)
		if r == nil || r.Status != model.ReachabilityReachable {
			t.Errorf("%s:%s: status = %v, want reachable", dep.Org, dep.Name, r)
		}
	}
}

func TestComputeReachablePackageHopsHandlesCycles(t *testing.T) {
	g := model.New()
	a := model.NewDependency(model.Dependency{Name: "a", Org: "g", Version: "1", Ecosystem: model.EcosystemMaven})
	b := model.NewDependency(model.Dependency{Name: "b", Org: "g", Version: "1", Ecosystem: model.EcosystemMaven})
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
	got := computeReachablePackageHops(g, map[string]struct{}{"g:a": {}})
	if h, ok := got[a.ID]; !ok || h != 0 {
		t.Errorf("expected a at hop 0: got=%v ok=%v", h, ok)
	}
	if h, ok := got[b.ID]; !ok || h != 1 {
		t.Errorf("expected b at hop 1 (transitive of a): got=%v ok=%v", h, ok)
	}
}

func TestAnalyzerApplicableRequiresJVMVulns(t *testing.T) {
	a := Analyzer{}

	g, reg := newSeed()
	pyDep := model.NewDependency(model.Dependency{Name: "requests", Ecosystem: model.EcosystemPython})
	pyDep.PackageRef = model.CanonicalPackageURLFromDependency(pyDep)
	_ = g.AddNode(pyDep)
	reg.Ensure(pyDep.PackageRef).Vulnerabilities = []model.Vulnerability{{ID: "x"}}
	if ok, _ := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg}); ok {
		t.Errorf("Applicable on python-only graph = true; want false")
	}

	g, reg = newSeed()
	addJVMDep(t, g, reg, t.TempDir(), "com.fasterxml.jackson.core", "jackson-databind", "1.0.0", model.Vulnerability{ID: "x"})
	if ok, _ := a.Applicable(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg}); !ok {
		t.Errorf("Applicable on jvm-with-vulns graph = false; want true")
	}
}

func TestAnalyzerMarksUnknownWhenNoProjectRootDiscovered(t *testing.T) {
	dir := t.TempDir()
	g, reg := newSeed()
	dep := addJVMDep(t, g, reg, dir, "com.fasterxml.jackson.core", "jackson-databind", "1.0.0", model.Vulnerability{ID: "x"})
	a := Analyzer{DisableCache: true, Runner: &fakeRunner{}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: dir}); err != nil {
		t.Fatal(err)
	}
	r := reachOf(t, reg, dep)
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
	if _, ok := got.ImportedArtifacts["java.util:list"]; ok {
		t.Errorf("stdlib leaked into import set")
	}
	if got.SourceFiles == 0 {
		t.Error("source files = 0; want > 0")
	}
}
