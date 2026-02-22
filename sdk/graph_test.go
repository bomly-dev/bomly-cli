package sdk

import (
	"slices"
	"strings"
	"testing"
)

func TestNewNode_BuildsIDFromNameAndVersion(t *testing.T) {
	n := NewPackageRef("react", "18.2.0")
	if n.ID != "react@18.2.0" {
		t.Fatalf("expected ID react@18.2.0, got %q", n.ID)
	}
}

func TestNewPackageNode_StoresCoordinatesAndBuildsID(t *testing.T) {
	n := NewPackage(Package{
		Ecosystem:   "maven",
		Name:        "demo-artifact:sources",
		Version:     "1.0.0",
		Org:         "com.example",
		BuildSystem: "maven",
	})

	if n.ID != "com.example:demo-artifact:sources@1.0.0" {
		t.Fatalf("expected qualified ID, got %q", n.ID)
	}
	if n.QualifiedName() != "com.example:demo-artifact:sources" {
		t.Fatalf("expected qualified name, got %q", n.QualifiedName())
	}
	if n.Ecosystem != "maven" || n.Org != "com.example" || n.BuildSystem != "maven" {
		t.Fatalf("unexpected coordinates on package: %#v", n)
	}
}

func TestAddNodeAndDependency_Success(t *testing.T) {
	g := New()
	app := NewPackageRef("app", "1.0.0")
	react := NewPackageRef("react", "18.2.0")

	if err := g.AddPackage(app); err != nil {
		t.Fatalf("add app package: %v", err)
	}
	if err := g.AddPackage(react); err != nil {
		t.Fatalf("add react package: %v", err)
	}
	if err := g.AddDependency(app.ID, react.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	deps, err := g.Dependencies(app.ID)
	if err != nil {
		t.Fatalf("dependencies: %v", err)
	}
	if len(deps) != 1 || deps[0].ID != react.ID {
		t.Fatalf("expected app to depend on react, got %#v", deps)
	}

	dependents, err := g.Dependents(react.ID)
	if err != nil {
		t.Fatalf("dependents: %v", err)
	}
	if len(dependents) != 1 || dependents[0].ID != app.ID {
		t.Fatalf("expected react dependent app, got %#v", dependents)
	}
}

func TestAddDependency_AllowsCycles(t *testing.T) {
	g := New()
	a := NewPackageRef("a", "")
	b := NewPackageRef("b", "")
	c := NewPackageRef("c", "")

	for _, n := range []*Package{a, b, c} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	if err := g.AddDependency(a.ID, b.ID); err != nil {
		t.Fatalf("add edge a->b: %v", err)
	}
	if err := g.AddDependency(b.ID, c.ID); err != nil {
		t.Fatalf("add edge b->c: %v", err)
	}
	if err := g.AddDependency(c.ID, a.ID); err != nil {
		t.Fatalf("add edge c->a: %v", err)
	}

	deps, err := g.Dependencies(c.ID)
	if err != nil {
		t.Fatalf("dependencies(c): %v", err)
	}
	if len(deps) != 1 || deps[0].ID != a.ID {
		t.Fatalf("expected c to depend on a, got %#v", deps)
	}
}

func TestTopologicalSort(t *testing.T) {
	g := New()
	app := NewPackageRef("app", "")
	api := NewPackageRef("api", "")
	log := NewPackageRef("log", "")
	util := NewPackageRef("util", "")

	for _, n := range []*Package{app, api, log, util} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	if err := g.AddDependency(app.ID, api.ID); err != nil {
		t.Fatalf("add app->api: %v", err)
	}
	if err := g.AddDependency(api.ID, util.ID); err != nil {
		t.Fatalf("add api->util: %v", err)
	}
	if err := g.AddDependency(app.ID, log.ID); err != nil {
		t.Fatalf("add app->log: %v", err)
	}

	order, err := g.TopologicalSort()
	if err != nil {
		t.Fatalf("topological sort: %v", err)
	}

	ids := make([]string, 0, len(order))
	for _, n := range order {
		ids = append(ids, n.ID)
	}

	assertBefore(t, ids, app.ID, api.ID)
	assertBefore(t, ids, app.ID, log.ID)
	assertBefore(t, ids, api.ID, util.ID)
}

func TestTopologicalSort_ReturnsPartialOrderOnCycle(t *testing.T) {
	g := New()
	a := NewPackageRef("a", "")
	b := NewPackageRef("b", "")
	c := NewPackageRef("c", "")

	for _, n := range []*Package{a, b, c} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	for _, edge := range [][2]string{{a.ID, b.ID}, {b.ID, a.ID}} {
		if err := g.AddDependency(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	order, err := g.TopologicalSort()
	if err != ErrCycleDetected {
		t.Fatalf("expected cycle error, got %v", err)
	}
	if got := idsOf(order); !slices.Equal(got, []string{"c"}) {
		t.Fatalf("expected partial order [c], got %#v", got)
	}
}

func TestRootsAndLeaves(t *testing.T) {
	g := New()
	app := NewPackageRef("app", "")
	react := NewPackageRef("react", "")
	lodash := NewPackageRef("lodash", "")

	for _, n := range []*Package{app, react, lodash} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	if err := g.AddDependency(app.ID, react.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	roots := idsOf(g.Roots())
	leaves := idsOf(g.Leaves())

	if !slices.Equal(roots, []string{"app", "lodash"}) {
		t.Fatalf("unexpected roots: %#v", roots)
	}
	if !slices.Equal(leaves, []string{"lodash", "react"}) {
		t.Fatalf("unexpected leaves: %#v", leaves)
	}
}

func TestCollectPathsTo_PrunesIrrelevantBranches(t *testing.T) {
	g := New()
	app := NewPackageRef("app", "")
	left := NewPackageRef("left", "")
	target := NewPackageRef("target", "")
	irrelevantA := NewPackageRef("irrelevant-a", "")
	irrelevantB := NewPackageRef("irrelevant-b", "")

	for _, n := range []*Package{app, left, target, irrelevantA, irrelevantB} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	for _, edge := range [][2]string{{app.ID, left.ID}, {left.ID, target.ID}, {app.ID, irrelevantA.ID}, {irrelevantA.ID, irrelevantB.ID}, {irrelevantB.ID, irrelevantA.ID}} {
		if err := g.AddDependency(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	paths, err := g.CollectPathsTo(target.ID)
	if err != nil {
		t.Fatalf("CollectPathsTo(): %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %#v", paths)
	}
	assertCollectedPath(t, paths[0], false, "", []string{"app", "left", "target"})
	for _, path := range paths {
		for _, pkg := range path.Packages {
			if strings.HasPrefix(pkg.ID, "irrelevant") {
				t.Fatalf("unexpected irrelevant package in path %#v", idsOf(path.Packages))
			}
		}
	}
}

func TestCollectPathsTo_RecordsTargetCycle(t *testing.T) {
	g := New()
	app := NewPackageRef("app", "")
	b := NewPackageRef("b", "")
	c := NewPackageRef("c", "")

	for _, n := range []*Package{app, b, c} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	for _, edge := range [][2]string{{app.ID, b.ID}, {b.ID, c.ID}, {c.ID, b.ID}} {
		if err := g.AddDependency(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	paths, err := g.CollectPathsTo(b.ID)
	if err != nil {
		t.Fatalf("CollectPathsTo(): %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %#v", paths)
	}
	assertCollectedPath(t, paths[0], false, "", []string{"app", "b"})
	assertCollectedPath(t, paths[1], true, b.ID, []string{"app", "b", "c", "b"})
}

func TestCollectPathsTo_RootlessCycleFallsBackToRelevantPackages(t *testing.T) {
	g := New()
	a := NewPackageRef("a", "")
	b := NewPackageRef("b", "")
	c := NewPackageRef("c", "")
	x := NewPackageRef("x", "")
	y := NewPackageRef("y", "")

	for _, n := range []*Package{a, b, c, x, y} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	for _, edge := range [][2]string{{a.ID, b.ID}, {b.ID, c.ID}, {c.ID, a.ID}, {x.ID, y.ID}, {y.ID, x.ID}} {
		if err := g.AddDependency(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	paths, err := g.CollectPathsTo(b.ID)
	if err != nil {
		t.Fatalf("CollectPathsTo(): %v", err)
	}
	if len(paths) != 4 {
		t.Fatalf("expected 4 paths, got %#v", paths)
	}
	assertCollectedPath(t, paths[0], false, "", []string{"a", "b"})
	assertCollectedPath(t, paths[1], false, "", []string{"b"})
	assertCollectedPath(t, paths[2], true, b.ID, []string{"b", "c", "a", "b"})
	assertCollectedPath(t, paths[3], false, "", []string{"c", "a", "b"})
}

func TestRemoveNode_RemovesIncidentEdges(t *testing.T) {
	g := New()
	a := NewPackageRef("a", "")
	b := NewPackageRef("b", "")
	c := NewPackageRef("c", "")

	for _, n := range []*Package{a, b, c} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	if err := g.AddDependency(a.ID, b.ID); err != nil {
		t.Fatalf("add a->b: %v", err)
	}
	if err := g.AddDependency(c.ID, b.ID); err != nil {
		t.Fatalf("add c->b: %v", err)
	}

	if ok := g.RemovePackage(b.ID); !ok {
		t.Fatalf("expected package b removal to succeed")
	}

	if _, ok := g.Package(b.ID); ok {
		t.Fatalf("expected package b removed")
	}
	if deps, err := g.Dependencies(a.ID); err != nil || len(deps) != 0 {
		t.Fatalf("expected a dependencies cleared, deps=%#v err=%v", deps, err)
	}
}

func TestPrettyString(t *testing.T) {
	g := New()
	app := NewPackageRef("app", "")
	react := NewPackageRef("react", "18.2.0")
	zod := NewPackageRef("zod", "")

	for _, n := range []*Package{app, react, zod} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	if err := g.AddDependency(app.ID, react.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	if err := g.AddDependency(app.ID, zod.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	got := g.PrettyString()
	want := "app -> [react@18.2.0, zod]\nreact@18.2.0 -> []\nzod -> []"
	if got != want {
		t.Fatalf("unexpected pretty string:\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestPrettyTree_WithSharedDependency(t *testing.T) {
	g := New()
	a := NewPackageRef("a", "")
	b := NewPackageRef("b", "")
	c := NewPackageRef("c", "")

	for _, n := range []*Package{a, b, c} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	if err := g.AddDependency(a.ID, b.ID); err != nil {
		t.Fatalf("add a->b: %v", err)
	}
	if err := g.AddDependency(c.ID, b.ID); err != nil {
		t.Fatalf("add c->b: %v", err)
	}

	got := g.PrettyTree()
	want := "a\n`-- b\nc\n`-- b (shared)"
	if got != want {
		t.Fatalf("unexpected pretty tree:\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestPrettyTree_WithCycle(t *testing.T) {
	g := New()
	app := NewPackageRef("app", "")
	a := NewPackageRef("a", "")
	b := NewPackageRef("b", "")

	for _, n := range []*Package{app, a, b} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	for _, edge := range [][2]string{{app.ID, a.ID}, {a.ID, b.ID}, {b.ID, a.ID}} {
		if err := g.AddDependency(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	got := g.PrettyTree()
	want := "app\n`-- a\n    `-- b\n        `-- a (cycle)"
	if got != want {
		t.Fatalf("unexpected pretty tree:\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestReAddNodeAfterRemove_ReusesGraphState(t *testing.T) {
	g := New()
	a := NewPackageRef("a", "")
	b := NewPackageRef("b", "")
	c := NewPackageRef("c", "")

	for _, n := range []*Package{a, b, c} {
		if err := g.AddPackage(n); err != nil {
			t.Fatalf("add package %q: %v", n.ID, err)
		}
	}
	if err := g.AddDependency(a.ID, b.ID); err != nil {
		t.Fatalf("add a->b: %v", err)
	}
	if err := g.AddDependency(c.ID, b.ID); err != nil {
		t.Fatalf("add c->b: %v", err)
	}

	if ok := g.RemovePackage(b.ID); !ok {
		t.Fatalf("remove b failed")
	}

	d := NewPackageRef("d", "")
	if err := g.AddPackage(d); err != nil {
		t.Fatalf("add d: %v", err)
	}
	if err := g.AddDependency(a.ID, d.ID); err != nil {
		t.Fatalf("add a->d: %v", err)
	}
	if err := g.AddDependency(c.ID, d.ID); err != nil {
		t.Fatalf("add c->d: %v", err)
	}

	if got := g.Size(); got != 3 {
		t.Fatalf("expected size 3, got %d", got)
	}
	deps, err := g.Dependencies(a.ID)
	if err != nil {
		t.Fatalf("dependencies(a): %v", err)
	}
	if len(deps) != 1 || deps[0].ID != d.ID {
		t.Fatalf("expected a to depend on d, got %#v", deps)
	}
}

func TestCompare_ClassifiesAddedRemovedAndUpdated(t *testing.T) {
	base := New()
	head := New()

	baseApp := NewPackageRef("app", "1.0.0")
	baseKeep := NewPackage(Package{Ecosystem: "npm", Name: "keep", Version: "1.0.0"})
	baseRemove := NewPackage(Package{Ecosystem: "npm", Name: "remove", Version: "1.0.0"})
	baseUpdate := NewPackage(Package{Ecosystem: "npm", Name: "update", Version: "1.0.0"})
	headApp := NewPackageRef("app", "1.0.0")
	headKeep := NewPackage(Package{Ecosystem: "npm", Name: "keep", Version: "1.0.0"})
	headAdd := NewPackage(Package{Ecosystem: "npm", Name: "add", Version: "2.0.0"})
	headUpdate := NewPackage(Package{Ecosystem: "npm", Name: "update", Version: "2.0.0"})

	for _, pkg := range []*Package{baseApp, baseKeep, baseRemove, baseUpdate} {
		if err := base.AddPackage(pkg); err != nil {
			t.Fatalf("base.AddPackage(%q): %v", pkg.ID, err)
		}
	}
	for _, pkg := range []*Package{headApp, headKeep, headAdd, headUpdate} {
		if err := head.AddPackage(pkg); err != nil {
			t.Fatalf("head.AddPackage(%q): %v", pkg.ID, err)
		}
	}

	diff := Compare(base, head)
	if got := idsOf(diff.Added); !slices.Equal(got, []string{"add@2.0.0"}) {
		t.Fatalf("unexpected added packages: %#v", got)
	}
	if got := idsOf(diff.Removed); !slices.Equal(got, []string{"remove@1.0.0"}) {
		t.Fatalf("unexpected removed packages: %#v", got)
	}
	if len(diff.Updated) != 1 {
		t.Fatalf("expected one updated package, got %#v", diff.Updated)
	}
	if diff.Updated[0].Before.ID != "update@1.0.0" || diff.Updated[0].After.ID != "update@2.0.0" {
		t.Fatalf("unexpected updated package: %#v", diff.Updated[0])
	}
}

func TestCompare_IgnoresSyntheticSubprojectRoots(t *testing.T) {
	base := New()
	head := New()
	for _, g := range []*Graph{base, head} {
		for _, pkg := range []*Package{
			NewPackageRefWithID("subproject:npm:root", "root", ""),
			NewPackage(Package{Ecosystem: "npm", Name: "shared", Version: "1.0.0"}),
		} {
			if err := g.AddPackage(pkg); err != nil {
				t.Fatalf("AddPackage(%q): %v", pkg.ID, err)
			}
		}
	}

	diff := Compare(base, head)
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Updated) != 0 {
		t.Fatalf("expected empty diff, got %#v", diff)
	}
}

func TestPackageHelpers(t *testing.T) {
	pkg := &Package{
		ID:      "pkg:generic/acme/demo@1.0.0",
		Org:     "acme",
		Name:    "demo",
		Version: "1.0.0",
		Licenses: []PackageLicense{
			{Value: "MIT"},
			{SPDXExpression: "Apache-2.0"},
			{},
		},
	}

	if got := pkg.DisplayName(); got != "acme:demo" {
		t.Fatalf("DisplayName() = %q, want %q", got, "acme:demo")
	}

	licenses := pkg.LicenseValues()
	if len(licenses) != 2 || licenses[0] != "Apache-2.0" || licenses[1] != "MIT" {
		t.Fatalf("LicenseValues() = %#v", licenses)
	}
}

func assertBefore(t *testing.T, ids []string, first, second string) {
	t.Helper()
	i := slices.Index(ids, first)
	j := slices.Index(ids, second)
	if i == -1 || j == -1 || i >= j {
		t.Fatalf("expected %q before %q in order %#v", first, second, ids)
	}
}

func idsOf(packages []*Package) []string {
	ids := make([]string, 0, len(packages))
	for _, n := range packages {
		ids = append(ids, n.ID)
	}
	return ids
}

func assertCollectedPath(t *testing.T, path Path, cyclic bool, cycleTo string, want []string) {
	t.Helper()
	if path.Cyclic != cyclic {
		t.Fatalf("expected cyclic=%t, got %#v", cyclic, path)
	}
	if path.CycleTo != cycleTo {
		t.Fatalf("expected cycleTo=%q, got %#v", cycleTo, path)
	}
	if got := idsOf(path.Packages); !slices.Equal(got, want) {
		t.Fatalf("expected path %v, got %v", want, got)
	}
}
