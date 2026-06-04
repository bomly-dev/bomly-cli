package jvmreach

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

type moduleFakeRunner struct {
	results map[string]RunnerResult
	errors  map[string]error
}

func (moduleFakeRunner) Name() string    { return "module-fake" }
func (moduleFakeRunner) Version() string { return "1" }
func (r moduleFakeRunner) Run(_ context.Context, projectDir string) (RunnerResult, error) {
	return r.results[projectDir], r.errors[projectDir]
}

func writeJVMFixture(t *testing.T, root, path, body string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverModuleHierarchiesParsesMavenModules(t *testing.T) {
	root := t.TempDir()
	writeJVMFixture(t, root, "pom.xml", `<project><groupId>com.example</groupId><artifactId>root</artifactId><modules><module>app</module><module>shared</module></modules></project>`)
	writeJVMFixture(t, root, "app/pom.xml", `<project><artifactId>app</artifactId></project>`)
	writeJVMFixture(t, root, "shared/pom.xml", `<project><artifactId>shared</artifactId></project>`)
	writeJVMFixture(t, root, "shared/src/main/java/com/example/shared/Helper.java", "package com.example.shared;\nclass Helper {}\n")

	hierarchies := discoverModuleHierarchies(model.AnalyzeRequest{ProjectPath: filepath.Join(root, "shared")})
	if len(hierarchies) != 1 || hierarchies[0].Root != root {
		t.Fatalf("hierarchies = %+v, want root %s", hierarchies, root)
	}
	var shared jvmModule
	for _, module := range hierarchies[0].Modules {
		if module.Dir == filepath.Join(root, "shared") {
			shared = module
		}
	}
	if shared.Coord != "com.example:shared" {
		t.Fatalf("shared coord = %q, want inherited Maven coordinate", shared.Coord)
	}
	if len(shared.Prefixes) != 1 || shared.Prefixes[0] != "com.example.shared" {
		t.Fatalf("shared prefixes = %v", shared.Prefixes)
	}
}

func TestDiscoverModuleHierarchiesParsesGradleIncludesAndOverrides(t *testing.T) {
	root := t.TempDir()
	writeJVMFixture(t, root, "settings.gradle.kts", "include(\":app\", \":shared\")\nproject(\":shared\").projectDir = file(\"libs/common\")\n")
	writeJVMFixture(t, root, "build.gradle.kts", "group = \"com.example\"\n")
	writeJVMFixture(t, root, "app/build.gradle.kts", "")
	writeJVMFixture(t, root, "libs/common/build.gradle.kts", "")

	hierarchies := discoverModuleHierarchies(model.AnalyzeRequest{ProjectPath: root})
	if len(hierarchies) != 1 {
		t.Fatalf("hierarchies = %+v", hierarchies)
	}
	dirs := make(map[string]struct{})
	for _, module := range hierarchies[0].Modules {
		dirs[module.Dir] = struct{}{}
	}
	for _, dir := range []string{root, filepath.Join(root, "app"), filepath.Join(root, "libs", "common")} {
		if _, ok := dirs[dir]; !ok {
			t.Fatalf("missing Gradle module %s in %v", dir, dirs)
		}
	}
}

func TestAnalyzerTraversesConsumedMavenModules(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "app")
	shared := filepath.Join(root, "shared")
	unused := filepath.Join(root, "unused")
	writeJVMFixture(t, root, "pom.xml", `<project><groupId>com.example</groupId><artifactId>root</artifactId><modules><module>app</module><module>shared</module><module>unused</module></modules></project>`)
	writeJVMFixture(t, root, "app/pom.xml", `<project><artifactId>app</artifactId></project>`)
	writeJVMFixture(t, root, "shared/pom.xml", `<project><artifactId>shared</artifactId></project>`)
	writeJVMFixture(t, root, "unused/pom.xml", `<project><artifactId>unused</artifactId></project>`)
	writeJVMFixture(t, root, "app/src/main/java/com/example/app/App.java", "package com.example.app;\nimport com.example.shared.Helper;\nclass App { static void main(String[] args) {} }\n")
	writeJVMFixture(t, root, "shared/src/main/java/com/example/shared/Helper.java", "package com.example.shared;\nimport com.fasterxml.jackson.databind.ObjectMapper;\nclass Helper {}\n")
	writeJVMFixture(t, root, "unused/src/main/java/com/example/unused/Unused.java", "package com.example.unused;\nimport org.apache.logging.log4j.LogManager;\nclass Unused {}\n")

	g := model.New()
	reg := model.NewPackageRegistry()
	jacksonPURL := "pkg:maven/com.fasterxml.jackson.core/jackson-databind@1"
	log4jPURL := "pkg:maven/org.apache.logging.log4j/log4j-core@1"
	jackson := model.NewDependency(model.Dependency{Name: "jackson-databind", Org: "com.fasterxml.jackson.core", Version: "1", Ecosystem: "maven", PURL: jacksonPURL})
	log4j := model.NewDependency(model.Dependency{Name: "log4j-core", Org: "org.apache.logging.log4j", Version: "1", Ecosystem: "maven", PURL: log4jPURL})
	reg.Ensure(jacksonPURL).Vulnerabilities = []model.Vulnerability{{ID: "jackson"}}
	reg.Ensure(log4jPURL).Vulnerabilities = []model.Vulnerability{{ID: "log4j"}}
	_ = g.AddNode(jackson)
	_ = g.AddNode(log4j)
	a := Analyzer{DisableCache: true, Runner: moduleFakeRunner{results: map[string]RunnerResult{
		root:   {},
		app:    {SourceFiles: 1, RawImports: map[string]struct{}{"com.example.shared.Helper": {}}},
		shared: {SourceFiles: 1, ImportedArtifacts: map[string]struct{}{"com.fasterxml.jackson.core:jackson-databind": {}}},
		unused: {SourceFiles: 1, ImportedArtifacts: map[string]struct{}{"org.apache.logging.log4j:log4j-core": {}}},
	}}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: root}); err != nil {
		t.Fatal(err)
	}
	if got := reg.Ensure(jacksonPURL).Vulnerabilities[0].Reachability; got == nil || got.Status != model.ReachabilityReachable || got.Hops == nil || *got.Hops != 1 {
		t.Fatalf("jackson reachability = %+v, want reachable at hop 1", got)
	}
	if got := reg.Ensure(log4jPURL).Vulnerabilities[0].Reachability; got == nil || got.Status != model.ReachabilityUnreachable {
		t.Fatalf("log4j reachability = %+v, want unreachable", got)
	}
}

func TestWalkSourceFilesPrunesNestedModules(t *testing.T) {
	root := t.TempDir()
	writeJVMFixture(t, root, "pom.xml", "<project></project>")
	writeJVMFixture(t, root, "src/main/java/Root.java", "class Root {}\n")
	writeJVMFixture(t, root, "child/pom.xml", "<project></project>")
	writeJVMFixture(t, root, "child/src/main/java/Child.java", "class Child {}\n")
	var files []string
	_, err := walkSourceFiles(root, func(path string) error {
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "Root.java" {
		t.Fatalf("walked files = %v, want root source only", files)
	}
}

func TestAnalyzeModuleHierarchyMarksConsumedFailureIncomplete(t *testing.T) {
	app, shared := filepath.Join(t.TempDir(), "app"), filepath.Join(t.TempDir(), "shared")
	hierarchy := moduleHierarchy{Root: filepath.Dir(app), Modules: []jvmModule{
		{Dir: app, Application: true, Prefixes: []string{"com.example.app"}},
		{Dir: shared, Prefixes: []string{"com.example.shared"}},
	}}
	runner := moduleFakeRunner{
		results: map[string]RunnerResult{
			app: {SourceFiles: 1, RawImports: map[string]struct{}{"com.example.shared.Helper": {}}},
		},
		errors: map[string]error{shared: errors.New("parse failed")},
	}
	closure, _, _ := (Analyzer{DisableCache: true}).analyzeModuleHierarchy(context.Background(), runner, nil, hierarchy, ensureLogger(nil))
	if !closure.incomplete || closure.reason != "module-closure-incomplete" {
		t.Fatalf("closure = %+v, want module closure incomplete", closure)
	}
}
