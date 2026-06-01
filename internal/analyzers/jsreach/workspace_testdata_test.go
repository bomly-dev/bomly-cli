package jsreach

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func workspaceFixture(name string) string {
	path, err := filepath.Abs(filepath.Join("testdata", "workspaces", name))
	if err != nil {
		return filepath.Join("testdata", "workspaces", name)
	}
	return path
}

func workspaceMemberNames(members []workspaceMember) []string {
	names := make([]string, 0, len(members))
	for _, member := range members {
		names = append(names, member.Name)
	}
	sort.Strings(names)
	return names
}

func TestDiscoverWorkspaceHierarchiesFromTestdata(t *testing.T) {
	tests := []struct {
		name      string
		start     string
		wantNames []string
	}{
		{
			name:  "npm array walks upward and recurses nested declarations",
			start: filepath.Join("npm-array", "nested", "children", "leaf"),
			wantNames: []string{
				"@company/app", "@company/leaf", "@company/nested",
				"@company/shared", "@company/unused", "npm-array-root",
			},
		},
		{
			name:      "yarn object",
			start:     filepath.Join("yarn-object", "packages", "app"),
			wantNames: []string{"@company/app", "yarn-object-root"},
		},
		{
			name:  "pnpm patterns and exclusions",
			start: filepath.Join("pnpm-patterns", "packages", "deep", "child"),
			wantNames: []string{
				"@company/app", "@company/deep-child", "pnpm-root",
			},
		},
		{
			name:      "standalone fallback",
			start:     "standalone",
			wantNames: []string{"standalone"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := workspaceFixture(tc.start)
			hierarchies := discoverWorkspaceHierarchies(model.AnalyzeRequest{ProjectPath: root})
			if len(hierarchies) != 1 {
				t.Fatalf("hierarchies = %+v, want one", hierarchies)
			}
			got := workspaceMemberNames(hierarchies[0].Members)
			sort.Strings(tc.wantNames)
			if !reflect.DeepEqual(got, tc.wantNames) {
				t.Fatalf("member names = %v, want %v", got, tc.wantNames)
			}
		})
	}
}

func TestDiscoverProjectRootsDeduplicatesGraphAndTargetSources(t *testing.T) {
	root := workspaceFixture("npm-array")
	g := model.New()
	pkg := model.NewPackage(model.Package{
		Name:      "lodash",
		Ecosystem: "npm",
		Locations: []model.PackageLocation{{RealPath: filepath.Join(root, "package-lock.json")}},
	})
	if err := g.AddPackage(pkg); err != nil {
		t.Fatal(err)
	}
	got := discoverProjectRoots(model.AnalyzeRequest{
		Graph:       g,
		ProjectPath: filepath.Join(root, "packages", "app"),
		ExecutionTarget: model.ExecutionTarget{
			Location: filepath.Join(root, "nested", "children", "leaf"),
		},
	})
	if !reflect.DeepEqual(got, []string{root}) {
		t.Fatalf("roots = %v, want [%s]", got, root)
	}
}

func TestDiscoverWorkspaceMembersDeduplicatesOverlappingPatterns(t *testing.T) {
	root := t.TempDir()
	writeJSFixture(t, root, "package.json", `{"name":"root","workspaces":["packages/*","packages/**"]}`)
	writeJSFixture(t, root, "packages/app/package.json", `{"name":"app"}`)
	if got := workspaceMemberNames(discoverWorkspaceMembers(root)); !reflect.DeepEqual(got, []string{"app", "root"}) {
		t.Fatalf("member names = %v, want each member once", got)
	}
}

func TestWorkspaceGlobMatch(t *testing.T) {
	tests := []struct {
		path, pattern string
		want          bool
	}{
		{"packages/app", "packages/*", true},
		{"packages/deep/app", "packages/*", false},
		{"packages/app", "packages/**", true},
		{"packages/deep/app", "packages/**", true},
		{"packages/app", "packages/**/app", true},
		{"packages/deep/app", "packages/**/app", true},
		{"packages/app", "packages/a?p", true},
		{"packages/amp", "packages/a?p", true},
		{"packages/ap", "packages/a?p", false},
		{"apps/app", "packages/**", false},
	}
	for _, tc := range tests {
		t.Run(tc.path+"_"+tc.pattern, func(t *testing.T) {
			if got := workspaceGlobMatch(tc.path, tc.pattern); got != tc.want {
				t.Fatalf("workspaceGlobMatch(%q, %q) = %v, want %v", tc.path, tc.pattern, got, tc.want)
			}
		})
	}
}

func TestWorkspacePathIncludedRespectsPatternOrder(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		want     bool
	}{
		{"included", "packages/app", []string{"packages/**"}, true},
		{"excluded", "packages/private/app", []string{"packages/**", "!packages/private/**"}, false},
		{"re-included", "packages/private/app", []string{"packages/**", "!packages/private/**", "packages/private/app"}, true},
		{"unmatched", "tools/app", []string{"packages/**"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := workspacePathIncluded(tc.path, tc.patterns); got != tc.want {
				t.Fatalf("workspacePathIncluded(%q, %v) = %v, want %v", tc.path, tc.patterns, got, tc.want)
			}
		})
	}
}

func TestDiscoverWorkspaceMembersSkipsIgnoredDirectories(t *testing.T) {
	root := t.TempDir()
	writeJSFixture(t, root, "package.json", `{"name":"root","workspaces":["**"]}`)
	for _, dir := range []string{"node_modules/pkg", ".git/pkg", "dist/pkg", "build/pkg", "coverage/pkg"} {
		writeJSFixture(t, root, filepath.Join(dir, "package.json"), `{"name":"ignored"}`)
	}
	writeJSFixture(t, root, "packages/app/package.json", `{"name":"app"}`)
	if got := workspaceMemberNames(discoverWorkspaceMembers(root)); !reflect.DeepEqual(got, []string{"app", "root"}) {
		t.Fatalf("member names = %v, want ignored directories pruned", got)
	}
}

func TestFindPackageJSONRootSkipsNodeModules(t *testing.T) {
	root := t.TempDir()
	writeJSFixture(t, root, "package.json", `{"name":"root"}`)
	nested := filepath.Join("node_modules", "dep")
	writeJSFixture(t, root, filepath.Join(nested, "package.json"), `{"name":"dep"}`)
	if got := findPackageJSONRoot(filepath.Join(root, nested)); got != root {
		t.Fatalf("findPackageJSONRoot() = %q, want %q", got, root)
	}
}

func TestAnalyzerBuiltInRunnerTraversesWorkspaceTestdata(t *testing.T) {
	root := workspaceFixture("npm-array")
	runner := NewRunner(nil)
	rootResult, err := runner.Run(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rootResult.ImportedPackages["@company/shared"]; !ok {
		t.Fatalf("root imports = %v, want @company/shared", rootResult.ImportedPackages)
	}
	sharedResult, err := runner.Run(context.Background(), filepath.Join(root, "packages", "shared"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sharedResult.ImportedPackages["lodash"]; !ok {
		t.Fatalf("shared imports = %v, want lodash", sharedResult.ImportedPackages)
	}
	g := model.New()
	lodash := model.NewPackage(model.Package{Name: "lodash", Version: "1", Ecosystem: "npm", Vulnerabilities: []model.PackageVulnerability{{ID: "lodash"}}})
	leftPad := model.NewPackage(model.Package{Name: "left-pad", Version: "1", Ecosystem: "npm", Vulnerabilities: []model.PackageVulnerability{{ID: "left-pad"}}})
	if err := g.AddPackage(lodash); err != nil {
		t.Fatal(err)
	}
	if err := g.AddPackage(leftPad); err != nil {
		t.Fatal(err)
	}
	if _, err := (Analyzer{DisableCache: true, Runner: runner}).Analyze(context.Background(), model.AnalyzeRequest{Graph: g, ProjectPath: root}); err != nil {
		t.Fatal(err)
	}
	if got := lodash.Vulnerabilities[0].Reachability; got == nil || got.Status != model.ReachabilityReachable || got.Hops == nil || *got.Hops != 1 {
		t.Fatalf("lodash reachability = %+v, want reachable at workspace hop 1", got)
	}
	if got := leftPad.Vulnerabilities[0].Reachability; got == nil || got.Status != model.ReachabilityUnreachable {
		t.Fatalf("left-pad reachability = %+v, want unreachable from unused workspace", got)
	}
}

func TestAnalyzeWorkspaceHierarchyIgnoresUnusedMemberFailure(t *testing.T) {
	root := t.TempDir()
	app, unused := filepath.Join(root, "app"), filepath.Join(root, "unused")
	hierarchy := workspaceHierarchy{Root: root, Members: []workspaceMember{{Name: "app", Dir: app}, {Name: "unused", Dir: unused}}}
	runner := workspaceFakeRunner{
		results: map[string]RunnerResult{
			app: {EntryPoints: []string{"index.js"}, ImportedPackages: map[string]struct{}{"lodash": {}}, DynamicImportsDetected: true},
		},
		errors: map[string]error{unused: errors.New("parse failed")},
	}
	closure, _, _ := (Analyzer{DisableCache: true}).analyzeWorkspaceHierarchy(context.Background(), runner, nil, hierarchy, ensureLogger(nil))
	if closure.incomplete {
		t.Fatalf("closure = %+v, unused failure must not taint the result", closure)
	}
	if !closure.dynamicImports {
		t.Fatal("dynamic import flag from consumed app was not propagated")
	}
	if got := closure.importedPackages["lodash"]; got != 0 {
		t.Fatalf("lodash depth = %d, want 0", got)
	}
}

func TestAnalyzeWorkspaceHierarchyUsesConsumerMemberWhenRootHasNoEntryPoint(t *testing.T) {
	root := t.TempDir()
	app, shared := filepath.Join(root, "app"), filepath.Join(root, "shared")
	hierarchy := workspaceHierarchy{Root: root, Members: []workspaceMember{{Name: "root", Dir: root}, {Name: "app", Dir: app}, {Name: "shared", Dir: shared}}}
	runner := workspaceFakeRunner{results: map[string]RunnerResult{
		root:   {},
		app:    {EntryPoints: []string{"app.js"}, ImportedPackages: map[string]struct{}{"shared": {}}},
		shared: {EntryPoints: []string{"shared.js"}, ImportedPackages: map[string]struct{}{"lodash": {}}},
	}}
	closure, _, _ := (Analyzer{DisableCache: true}).analyzeWorkspaceHierarchy(context.Background(), runner, nil, hierarchy, ensureLogger(nil))
	if closure.incomplete {
		t.Fatalf("closure = %+v", closure)
	}
	if got := closure.importedPackages["lodash"]; got != 1 {
		t.Fatalf("lodash depth = %d, want 1", got)
	}
}

func TestAnalyzeWorkspaceHierarchyHandlesInternalCycle(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	hierarchy := workspaceHierarchy{Root: root, Members: []workspaceMember{{Name: "a", Dir: a}, {Name: "b", Dir: b}}}
	runner := workspaceFakeRunner{results: map[string]RunnerResult{
		a: {EntryPoints: []string{"a.js"}, ImportedPackages: map[string]struct{}{"b": {}}},
		b: {EntryPoints: []string{"b.js"}, ImportedPackages: map[string]struct{}{"a": {}, "lodash": {}}},
	}}
	closure, _, _ := (Analyzer{DisableCache: true}).analyzeWorkspaceHierarchy(context.Background(), runner, nil, hierarchy, ensureLogger(nil))
	if closure.incomplete {
		t.Fatalf("closure = %+v", closure)
	}
	if got := closure.importedPackages["lodash"]; got != 0 {
		t.Fatalf("lodash depth = %d, want 0 from cycle fallback roots", got)
	}
}

func TestReadWorkspacePatternsToleratesMalformedManifest(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readWorkspacePatterns(root); len(got) != 0 {
		t.Fatalf("patterns = %v, want none", got)
	}
}

func TestReadPackageNameReturnsEmptyForMissingAndMalformedManifest(t *testing.T) {
	root := t.TempDir()
	if got := readPackageName(root); got != "" {
		t.Fatalf("missing package name = %q, want empty", got)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readPackageName(root); got != "" {
		t.Fatalf("malformed package name = %q, want empty", got)
	}
}
