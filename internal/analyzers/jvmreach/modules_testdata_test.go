package jvmreach

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func moduleFixture(name string) string {
	path, err := filepath.Abs(filepath.Join("testdata", "modules", name))
	if err != nil {
		return filepath.Join("testdata", "modules", name)
	}
	return path
}

func modulesByRelativeDir(root string, modules []jvmModule) map[string]jvmModule {
	out := make(map[string]jvmModule, len(modules))
	for _, module := range modules {
		rel, err := filepath.Rel(root, module.Dir)
		if err != nil {
			continue
		}
		out[filepath.ToSlash(rel)] = module
	}
	return out
}

func TestDiscoverModuleHierarchiesFromTestdata(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		start     string
		wantCoord map[string]string
	}{
		{
			name:    "recursive Maven reactor walks upward and inherits group",
			fixture: "maven-reactor",
			start:   filepath.Join("libs", "shared"),
			wantCoord: map[string]string{
				".":             "com.example:root",
				"app":           "com.example:app",
				"libs":          "com.example:libs",
				"libs/shared":   "com.example:shared",
				"libs/specific": "com.example:specific",
				"unused":        "com.example:unused",
			},
		},
		{
			name:    "Groovy Gradle settings and projectDir override",
			fixture: "gradle-groovy",
			start:   filepath.Join("libs", "common"),
			wantCoord: map[string]string{
				".":           "",
				"app":         "com.example.app:app",
				"libs/common": "com.example.libs:common",
				"unused":      "com.example:unused",
			},
		},
		{
			name:    "multiline Kotlin Gradle settings and nested project path",
			fixture: "gradle-kotlin",
			start:   filepath.Join("nested", "shared"),
			wantCoord: map[string]string{
				".":             "",
				"app":           "com.example:app",
				"nested/shared": "com.example.nested:shared",
			},
		},
		{
			name:    "standalone SBT fallback",
			fixture: "sbt-standalone",
			start:   ".",
			wantCoord: map[string]string{
				".": "",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := moduleFixture(tc.fixture)
			hierarchies := discoverModuleHierarchies(model.AnalyzeRequest{ProjectPath: filepath.Join(root, tc.start)})
			if len(hierarchies) != 1 {
				t.Fatalf("hierarchies = %+v, want one", hierarchies)
			}
			if hierarchies[0].Root != root {
				t.Fatalf("root = %q, want %q", hierarchies[0].Root, root)
			}
			got := modulesByRelativeDir(root, hierarchies[0].Modules)
			if len(got) != len(tc.wantCoord) {
				t.Fatalf("modules = %+v, want coords %v", got, tc.wantCoord)
			}
			for rel, coord := range tc.wantCoord {
				if got[rel].Coord != coord {
					t.Fatalf("%s coord = %q, want %q", rel, got[rel].Coord, coord)
				}
			}
		})
	}
}

func TestGradleIncludedProjectPaths(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"Groovy line", "include ':app', ':shared'\n", []string{":app", ":shared"}},
		{"Groovy line with Windows endings", "include ':app', ':shared'\r\n", []string{":app", ":shared"}},
		{"Kotlin single line", "include(\":app\", \":shared\")\n", []string{":app", ":shared"}},
		{"Kotlin multiline", "include(\n  \":app\",\n  \":nested:shared\",\n)\n", []string{":app", ":nested:shared"}},
		{"deduplicated", "include ':app'\ninclude(\":app\")\n", []string{":app"}},
		{"composite ignored", "includeBuild(\"../other\")\n", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := gradleIncludedProjectPaths(tc.body); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("paths = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDiscoverProjectRootsDeduplicatesGraphAndTargetSources(t *testing.T) {
	root := moduleFixture("maven-reactor")
	g := model.New()
	pkg := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "jackson-databind",
		Org:       "com.fasterxml.jackson.core",
		Ecosystem: "maven"}, Locations: []model.PackageLocation{{RealPath: filepath.Join(root, "app", "pom.xml")}},
	})
	if err := g.AddNode(pkg); err != nil {
		t.Fatal(err)
	}
	got := discoverProjectRoots(model.AnalyzeRequest{
		Graph:       g,
		ProjectPath: filepath.Join(root, "libs", "shared"),
		ExecutionTarget: model.ExecutionTarget{
			Location: filepath.Join(root, "unused"),
		},
	})
	if !reflect.DeepEqual(got, []string{root}) {
		t.Fatalf("roots = %v, want [%s]", got, root)
	}
}

func TestReadGradleModulesRejectsEscapingProjectDirOverride(t *testing.T) {
	root := t.TempDir()
	writeJVMFixture(t, root, "settings.gradle", "include ':outside'\nproject(':outside').projectDir = file('../outside')\n")
	if got := readGradleModules(root); len(got) != 0 {
		t.Fatalf("modules = %+v, want escaping override ignored", got)
	}
}

func TestReadMavenProjectRejectsMissingAndMalformedManifest(t *testing.T) {
	root := t.TempDir()
	if _, ok := readMavenProject(root); ok {
		t.Fatal("missing pom.xml unexpectedly parsed")
	}
	writeJVMFixture(t, root, "pom.xml", "<project>")
	if _, ok := readMavenProject(root); ok {
		t.Fatal("malformed pom.xml unexpectedly parsed")
	}
}

func TestResolveInternalModuleUsesLongestComponentPrefix(t *testing.T) {
	modules := []jvmModule{
		{Dir: "shared", Prefixes: []string{"com.example.shared"}},
		{Dir: "specific", Prefixes: []string{"com.example.shared.specific"}},
	}
	tests := []struct {
		imported string
		wantDir  string
		wantOK   bool
	}{
		{"com.example.shared.Helper", "shared", true},
		{"com.example.shared.specific.Helper", "specific", true},
		{"com.example.sharedness.Helper", "", false},
		{"org.example.Other", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.imported, func(t *testing.T) {
			got, ok := resolveInternalModule(tc.imported, modules)
			if ok != tc.wantOK || got.Dir != tc.wantDir {
				t.Fatalf("resolveInternalModule(%q) = (%+v, %v), want dir=%q ok=%v", tc.imported, got, ok, tc.wantDir, tc.wantOK)
			}
		})
	}
}

func TestModuleHasApplicationEntryPoint(t *testing.T) {
	tests := []struct {
		name, source string
		want         bool
	}{
		{"Java main", "class App { static void main(String[] args) {} }\n", true},
		{"Kotlin main", "fun main() {}\n", true},
		{"Spring Boot", "@SpringBootApplication\nclass App {}\n", true},
		{"Scala App", "object Main extends App {}\n", true},
		{"library", "class Helper {}\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeJVMFixture(t, root, "pom.xml", "<project></project>")
			writeJVMFixture(t, root, "src/main/java/App.java", tc.source)
			if got := moduleHasApplicationEntryPoint(root); got != tc.want {
				t.Fatalf("moduleHasApplicationEntryPoint() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDiscoverSourcePrefixesSortsLongestFirstAndDeduplicates(t *testing.T) {
	root := t.TempDir()
	writeJVMFixture(t, root, "pom.xml", "<project></project>")
	writeJVMFixture(t, root, "src/main/java/A.java", "package com.example;\nclass A {}\n")
	writeJVMFixture(t, root, "src/main/java/B.java", "package com.example.deep;\nclass B {}\n")
	writeJVMFixture(t, root, "src/main/java/C.java", "package com.example;\nclass C {}\n")
	if got, want := discoverSourcePrefixes(root), []string{"com.example.deep", "com.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
}

func TestAnalyzerBuiltInRunnerTraversesMavenReactorTestdata(t *testing.T) {
	root := moduleFixture("maven-reactor")
	g := model.New()
	reg := model.NewPackageRegistry()
	jacksonPURL := "pkg:maven/com.fasterxml.jackson.core/jackson-databind@1"
	log4jPURL := "pkg:maven/org.apache.logging.log4j/log4j-core@1"
	jackson := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "jackson-databind", Org: "com.fasterxml.jackson.core", Version: "1", Ecosystem: "maven", PURL: jacksonPURL}})
	log4j := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "log4j-core", Org: "org.apache.logging.log4j", Version: "1", Ecosystem: "maven", PURL: log4jPURL}})
	reg.Ensure(jacksonPURL).Vulnerabilities = []model.Vulnerability{{ID: "jackson"}}
	reg.Ensure(log4jPURL).Vulnerabilities = []model.Vulnerability{{ID: "log4j"}}
	if err := g.AddNode(jackson); err != nil {
		t.Fatal(err)
	}
	if err := g.AddNode(log4j); err != nil {
		t.Fatal(err)
	}
	if _, err := (Analyzer{DisableCache: true}).Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: root}); err != nil {
		t.Fatal(err)
	}
	if got := reg.Ensure(jacksonPURL).Vulnerabilities[0].Reachability; got == nil || got.Status != model.ReachabilityReachable || got.Hops == nil || *got.Hops != 1 {
		t.Fatalf("jackson reachability = %+v, want reachable at module hop 1", got)
	}
	if got := reg.Ensure(log4jPURL).Vulnerabilities[0].Reachability; got == nil || got.Status != model.ReachabilityUnreachable {
		t.Fatalf("log4j reachability = %+v, want unreachable from unused module", got)
	}
}

func TestAnalyzeModuleHierarchyUsesConsumerFallbackWithoutApplicationEntryPoint(t *testing.T) {
	root := t.TempDir()
	lib, shared := filepath.Join(root, "lib"), filepath.Join(root, "shared")
	hierarchy := moduleHierarchy{Root: root, Modules: []jvmModule{
		{Dir: lib, Prefixes: []string{"com.example.lib"}},
		{Dir: shared, Prefixes: []string{"com.example.shared"}},
	}}
	runner := moduleFakeRunner{results: map[string]RunnerResult{
		lib:    {SourceFiles: 1, RawImports: map[string]struct{}{"com.example.shared.Helper": {}}},
		shared: {SourceFiles: 1, ImportedArtifacts: map[string]struct{}{"com.fasterxml.jackson.core:jackson-databind": {}}},
	}}
	closure, _, _ := (Analyzer{DisableCache: true}).analyzeModuleHierarchy(context.Background(), runner, nil, hierarchy, ensureLogger(nil))
	if closure.incomplete {
		t.Fatalf("closure = %+v", closure)
	}
	if got := closure.importedArtifacts["com.fasterxml.jackson.core:jackson-databind"]; got != 1 {
		t.Fatalf("jackson depth = %d, want 1", got)
	}
}

func TestAnalyzeModuleHierarchyIgnoresUnusedFailure(t *testing.T) {
	root := t.TempDir()
	app, unused := filepath.Join(root, "app"), filepath.Join(root, "unused")
	hierarchy := moduleHierarchy{Root: root, Modules: []jvmModule{
		{Dir: app, Application: true, Prefixes: []string{"com.example.app"}},
		{Dir: unused, Prefixes: []string{"com.example.unused"}},
	}}
	runner := moduleFakeRunner{
		results: map[string]RunnerResult{
			app: {SourceFiles: 1, ImportedArtifacts: map[string]struct{}{"com.fasterxml.jackson.core:jackson-databind": {}}, DynamicImportsDetected: true},
		},
		errors: map[string]error{unused: os.ErrPermission},
	}
	closure, _, _ := (Analyzer{DisableCache: true}).analyzeModuleHierarchy(context.Background(), runner, nil, hierarchy, ensureLogger(nil))
	if closure.incomplete {
		t.Fatalf("closure = %+v, unused failure must not taint the result", closure)
	}
	if !closure.dynamicImports {
		t.Fatal("dynamic import flag from consumed app was not propagated")
	}
}

func TestAnalyzeModuleHierarchyHandlesInternalCycle(t *testing.T) {
	root := t.TempDir()
	app, shared := filepath.Join(root, "app"), filepath.Join(root, "shared")
	hierarchy := moduleHierarchy{Root: root, Modules: []jvmModule{
		{Dir: app, Application: true, Prefixes: []string{"com.example.app"}},
		{Dir: shared, Prefixes: []string{"com.example.shared"}},
	}}
	runner := moduleFakeRunner{results: map[string]RunnerResult{
		app: {
			SourceFiles: 1,
			RawImports:  map[string]struct{}{"com.example.shared.Helper": {}},
		},
		shared: {
			SourceFiles:       1,
			RawImports:        map[string]struct{}{"com.example.app.App": {}},
			ImportedArtifacts: map[string]struct{}{"com.fasterxml.jackson.core:jackson-databind": {}},
		},
	}}
	closure, _, _ := (Analyzer{DisableCache: true}).analyzeModuleHierarchy(context.Background(), runner, nil, hierarchy, ensureLogger(nil))
	if closure.incomplete {
		t.Fatalf("closure = %+v", closure)
	}
	if got := closure.importedArtifacts["com.fasterxml.jackson.core:jackson-databind"]; got != 1 {
		t.Fatalf("jackson depth = %d, want 1", got)
	}
}

func TestWalkersPruneNestedModules(t *testing.T) {
	root := t.TempDir()
	writeJVMFixture(t, root, "pom.xml", "<project></project>")
	writeJVMFixture(t, root, "src/main/java/Root.java", "class Root {}\n")
	writeJVMFixture(t, root, "child/pom.xml", "<project></project>")
	writeJVMFixture(t, root, "child/src/main/java/Child.java", "class Child { void load(String name) { Class.forName(name); } }\n")
	var files []string
	_, err := walkSourceFiles(root, func(path string) error {
		files = append(files, filepath.Base(path))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	if !reflect.DeepEqual(files, []string{"Root.java"}) {
		t.Fatalf("walked files = %v, want root source only", files)
	}
	if detectDynamicImports(root) {
		t.Fatal("nested-module dynamic import leaked into parent module scan")
	}
}
