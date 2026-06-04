package jsreach

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

type workspaceFakeRunner struct {
	results map[string]RunnerResult
	errors  map[string]error
}

func (workspaceFakeRunner) Name() string    { return "workspace-fake" }
func (workspaceFakeRunner) Version() string { return "1" }
func (r workspaceFakeRunner) Run(_ context.Context, projectDir string) (RunnerResult, error) {
	return r.results[projectDir], r.errors[projectDir]
}

func writeJSFixture(t *testing.T, root, path, body string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverWorkspaceHierarchiesSupportsManifestForms(t *testing.T) {
	tests := []struct {
		name     string
		rootBody string
		extra    map[string]string
	}{
		{name: "array", rootBody: `{"name":"root","workspaces":["packages/*"]}`},
		{name: "object", rootBody: `{"name":"root","workspaces":{"packages":["packages/*"]}}`},
		{
			name:     "pnpm with negation",
			rootBody: `{"name":"root"}`,
			extra: map[string]string{
				"pnpm-workspace.yaml": "packages:\n  - packages/**\n  - '!packages/excluded'\n",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeJSFixture(t, root, "package.json", tc.rootBody)
			writeJSFixture(t, root, "packages/app/package.json", `{"name":"@company/app"}`)
			writeJSFixture(t, root, "packages/excluded/package.json", `{"name":"@company/excluded"}`)
			for path, body := range tc.extra {
				writeJSFixture(t, root, path, body)
			}
			hierarchies := discoverWorkspaceHierarchies(model.AnalyzeRequest{ProjectPath: filepath.Join(root, "packages", "app")})
			if len(hierarchies) != 1 || hierarchies[0].Root != root {
				t.Fatalf("hierarchies = %+v, want root %s", hierarchies, root)
			}
			names := make(map[string]struct{})
			for _, member := range hierarchies[0].Members {
				names[member.Name] = struct{}{}
			}
			if _, ok := names["@company/app"]; !ok {
				t.Fatalf("app workspace missing: %v", names)
			}
			_, excluded := names["@company/excluded"]
			if tc.name == "pnpm with negation" && excluded {
				t.Fatalf("negated pnpm workspace included: %v", names)
			}
		})
	}
}

func TestDiscoverWorkspaceHierarchiesRecursesNestedDeclarations(t *testing.T) {
	root := t.TempDir()
	writeJSFixture(t, root, "package.json", `{"name":"root","workspaces":["packages/*"]}`)
	writeJSFixture(t, root, "packages/nested/package.json", `{"name":"nested","workspaces":["children/*"]}`)
	writeJSFixture(t, root, "packages/nested/children/app/package.json", `{"name":"app"}`)
	hierarchies := discoverWorkspaceHierarchies(model.AnalyzeRequest{ProjectPath: root})
	if len(hierarchies) != 1 {
		t.Fatalf("hierarchies = %+v", hierarchies)
	}
	names := make(map[string]struct{})
	for _, member := range hierarchies[0].Members {
		names[member.Name] = struct{}{}
	}
	if _, ok := names["app"]; !ok {
		t.Fatalf("nested workspace missing: %v", names)
	}
}

func TestAnalyzerTraversesConsumedWorkspaceMembers(t *testing.T) {
	root := t.TempDir()
	writeJSFixture(t, root, "package.json", `{"name":"app","workspaces":["packages/*"],"main":"index.js"}`)
	writeJSFixture(t, root, "index.js", "")
	shared := filepath.Join(root, "packages", "shared")
	unused := filepath.Join(root, "packages", "unused")
	writeJSFixture(t, root, "packages/shared/package.json", `{"name":"@company/shared","main":"index.js"}`)
	writeJSFixture(t, root, "packages/shared/index.js", "")
	writeJSFixture(t, root, "packages/unused/package.json", `{"name":"@company/unused","main":"index.js"}`)
	writeJSFixture(t, root, "packages/unused/index.js", "")

	g := model.New()
	reg := model.NewPackageRegistry()
	lodashPURL := "pkg:npm/lodash@1"
	leftPadPURL := "pkg:npm/left-pad@1"
	lodash := model.NewDependency(model.Dependency{Name: "lodash", Version: "1", Ecosystem: "npm", PURL: lodashPURL})
	leftPad := model.NewDependency(model.Dependency{Name: "left-pad", Version: "1", Ecosystem: "npm", PURL: leftPadPURL})
	reg.Ensure(lodashPURL).Vulnerabilities = []model.Vulnerability{{ID: "lodash"}}
	reg.Ensure(leftPadPURL).Vulnerabilities = []model.Vulnerability{{ID: "left-pad"}}
	_ = g.AddNode(lodash)
	_ = g.AddNode(leftPad)
	a := Analyzer{DisableCache: true, Runner: workspaceFakeRunner{results: map[string]RunnerResult{
		root:   {EntryPoints: []string{filepath.Join(root, "index.js")}, ImportedPackages: map[string]struct{}{"@company/shared": {}}},
		shared: {EntryPoints: []string{filepath.Join(shared, "index.js")}, ImportedPackages: map[string]struct{}{"lodash": {}}},
		unused: {EntryPoints: []string{filepath.Join(unused, "index.js")}, ImportedPackages: map[string]struct{}{"left-pad": {}}},
	}}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: root}); err != nil {
		t.Fatal(err)
	}
	if got := reg.Ensure(lodashPURL).Vulnerabilities[0].Reachability; got == nil || got.Status != model.ReachabilityReachable || got.Hops == nil || *got.Hops != 1 {
		t.Fatalf("lodash reachability = %+v, want reachable at hop 1", got)
	}
	if got := reg.Ensure(leftPadPURL).Vulnerabilities[0].Reachability; got == nil || got.Status != model.ReachabilityUnreachable {
		t.Fatalf("left-pad reachability = %+v, want unreachable", got)
	}
}

func TestAnalyzerMarksWorkspaceClosureIncomplete(t *testing.T) {
	root := t.TempDir()
	writeJSFixture(t, root, "package.json", `{"name":"app","workspaces":["packages/*"],"main":"index.js"}`)
	writeJSFixture(t, root, "index.js", "")
	shared := filepath.Join(root, "packages", "shared")
	writeJSFixture(t, root, "packages/shared/package.json", `{"name":"@company/shared","main":"index.js"}`)
	writeJSFixture(t, root, "packages/shared/index.js", "")
	g, reg, lodashPURL := newNPMGraph(t, "lodash", "1", model.Vulnerability{ID: "lodash"})
	a := Analyzer{DisableCache: true, Runner: workspaceFakeRunner{
		results: map[string]RunnerResult{root: {EntryPoints: []string{filepath.Join(root, "index.js")}, ImportedPackages: map[string]struct{}{"@company/shared": {}}}},
		errors:  map[string]error{shared: errors.New("parse failed")},
	}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg, ProjectPath: root}); err != nil {
		t.Fatal(err)
	}
	if got := reg.Ensure(lodashPURL).Vulnerabilities[0].Reachability; got == nil || got.Status != model.ReachabilityUnknown || got.Reason != "workspace-closure-incomplete" {
		t.Fatalf("reachability = %+v, want workspace closure unknown", got)
	}
}

// newNPMGraph builds a single-node npm graph and an accompanying
// PURL-keyed registry that carries vulns. Returns (graph, registry, purl).
func newNPMGraph(t *testing.T, name, version string, vulns ...model.Vulnerability) (*model.Graph, *model.PackageRegistry, string) {
	t.Helper()
	purl := "pkg:npm/" + name + "@" + version
	g := model.New()
	dep := model.NewDependency(model.Dependency{Name: name, Version: version, Ecosystem: "npm", PURL: purl})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add node: %v", err)
	}
	reg := model.NewPackageRegistry()
	reg.Ensure(purl).Vulnerabilities = vulns
	return g, reg, purl
}
