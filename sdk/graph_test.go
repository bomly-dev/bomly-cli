package sdk

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestNewNode_BuildsIDFromNameAndVersion(t *testing.T) {
	n := NewDependencyRef("react", "18.2.0")
	if n.ID != "react@18.2.0" {
		t.Fatalf("expected ID react@18.2.0, got %q", n.ID)
	}
}

func TestNewDependencyNode_StoresCoordinatesAndBuildsID(t *testing.T) {
	n := NewDependency(Dependency{Coordinates: Coordinates{Ecosystem: EcosystemMaven,
		Name:           "demo-artifact:sources",
		Version:        "1.0.0",
		Org:            "com.example",
		PackageManager: PackageManagerMaven},
	})

	if n.ID != "com.example:demo-artifact:sources@1.0.0" {
		t.Fatalf("expected qualified ID, got %q", n.ID)
	}
	if n.QualifiedName() != "com.example:demo-artifact:sources" {
		t.Fatalf("expected qualified name, got %q", n.QualifiedName())
	}
	if n.Ecosystem != EcosystemMaven || n.Org != "com.example" || n.PackageManager != PackageManagerMaven {
		t.Fatalf("unexpected coordinates on dependency: %#v", n)
	}
}

func TestAddNodeAndDependency_Success(t *testing.T) {
	g := New()
	app := NewDependencyRef("app", "1.0.0")
	react := NewDependencyRef("react", "18.2.0")

	if err := g.AddNode(app); err != nil {
		t.Fatalf("add app node: %v", err)
	}
	if err := g.AddNode(react); err != nil {
		t.Fatalf("add react node: %v", err)
	}
	if err := g.AddEdge(app.ID, react.ID); err != nil {
		t.Fatalf("add edge: %v", err)
	}

	deps, err := g.DirectDependencies(app.ID)
	if err != nil {
		t.Fatalf("direct dependencies: %v", err)
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

func TestAddEdge_AllowsCycles(t *testing.T) {
	g := New()
	a := NewDependencyRef("a", "")
	b := NewDependencyRef("b", "")
	c := NewDependencyRef("c", "")

	for _, n := range []*Dependency{a, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(a.ID, b.ID); err != nil {
		t.Fatalf("add edge a->b: %v", err)
	}
	if err := g.AddEdge(b.ID, c.ID); err != nil {
		t.Fatalf("add edge b->c: %v", err)
	}
	if err := g.AddEdge(c.ID, a.ID); err != nil {
		t.Fatalf("add edge c->a: %v", err)
	}

	deps, err := g.DirectDependencies(c.ID)
	if err != nil {
		t.Fatalf("direct dependencies(c): %v", err)
	}
	if len(deps) != 1 || deps[0].ID != a.ID {
		t.Fatalf("expected c to depend on a, got %#v", deps)
	}
}

func TestTopologicalSort(t *testing.T) {
	g := New()
	app := NewDependencyRef("app", "")
	api := NewDependencyRef("api", "")
	log := NewDependencyRef("log", "")
	util := NewDependencyRef("util", "")

	for _, n := range []*Dependency{app, api, log, util} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(app.ID, api.ID); err != nil {
		t.Fatalf("add app->api: %v", err)
	}
	if err := g.AddEdge(api.ID, util.ID); err != nil {
		t.Fatalf("add api->util: %v", err)
	}
	if err := g.AddEdge(app.ID, log.ID); err != nil {
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
	a := NewDependencyRef("a", "")
	b := NewDependencyRef("b", "")
	c := NewDependencyRef("c", "")

	for _, n := range []*Dependency{a, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	for _, edge := range [][2]string{{a.ID, b.ID}, {b.ID, a.ID}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	order, err := g.TopologicalSort()
	if !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("expected cycle error, got %v", err)
	}
	if got := idsOf(order); !slices.Equal(got, []string{"c"}) {
		t.Fatalf("expected partial order [c], got %#v", got)
	}
}

func TestRootsAndLeaves(t *testing.T) {
	g := New()
	app := NewDependencyRef("app", "")
	react := NewDependencyRef("react", "")
	lodash := NewDependencyRef("lodash", "")

	for _, n := range []*Dependency{app, react, lodash} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(app.ID, react.ID); err != nil {
		t.Fatalf("add edge: %v", err)
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
	app := NewDependencyRef("app", "")
	left := NewDependencyRef("left", "")
	target := NewDependencyRef("target", "")
	irrelevantA := NewDependencyRef("irrelevant-a", "")
	irrelevantB := NewDependencyRef("irrelevant-b", "")

	for _, n := range []*Dependency{app, left, target, irrelevantA, irrelevantB} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	for _, edge := range [][2]string{{app.ID, left.ID}, {left.ID, target.ID}, {app.ID, irrelevantA.ID}, {irrelevantA.ID, irrelevantB.ID}, {irrelevantB.ID, irrelevantA.ID}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
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
		for _, node := range path.Nodes {
			if strings.HasPrefix(node.ID, "irrelevant") {
				t.Fatalf("unexpected irrelevant node in path %#v", idsOf(path.Nodes))
			}
		}
	}
}

func TestCollectPathsTo_RecordsTargetCycle(t *testing.T) {
	g := New()
	app := NewDependencyRef("app", "")
	b := NewDependencyRef("b", "")
	c := NewDependencyRef("c", "")

	for _, n := range []*Dependency{app, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	for _, edge := range [][2]string{{app.ID, b.ID}, {b.ID, c.ID}, {c.ID, b.ID}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
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

func TestCollectPathsTo_RootlessCycleFallsBackToRelevantNodes(t *testing.T) {
	g := New()
	a := NewDependencyRef("a", "")
	b := NewDependencyRef("b", "")
	c := NewDependencyRef("c", "")
	x := NewDependencyRef("x", "")
	y := NewDependencyRef("y", "")

	for _, n := range []*Dependency{a, b, c, x, y} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	for _, edge := range [][2]string{{a.ID, b.ID}, {b.ID, c.ID}, {c.ID, a.ID}, {x.ID, y.ID}, {y.ID, x.ID}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
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
	a := NewDependencyRef("a", "")
	b := NewDependencyRef("b", "")
	c := NewDependencyRef("c", "")

	for _, n := range []*Dependency{a, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(a.ID, b.ID); err != nil {
		t.Fatalf("add a->b: %v", err)
	}
	if err := g.AddEdge(c.ID, b.ID); err != nil {
		t.Fatalf("add c->b: %v", err)
	}

	if ok := g.RemoveNode(b.ID); !ok {
		t.Fatalf("expected node b removal to succeed")
	}

	if _, ok := g.Node(b.ID); ok {
		t.Fatalf("expected node b removed")
	}
	if deps, err := g.DirectDependencies(a.ID); err != nil || len(deps) != 0 {
		t.Fatalf("expected a dependencies cleared, deps=%#v err=%v", deps, err)
	}
}

func TestPrettyString(t *testing.T) {
	g := New()
	app := NewDependencyRef("app", "")
	react := NewDependencyRef("react", "18.2.0")
	zod := NewDependencyRef("zod", "")

	for _, n := range []*Dependency{app, react, zod} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(app.ID, react.ID); err != nil {
		t.Fatalf("add edge: %v", err)
	}
	if err := g.AddEdge(app.ID, zod.ID); err != nil {
		t.Fatalf("add edge: %v", err)
	}

	got := g.PrettyString()
	want := "app -> [react@18.2.0, zod]\nreact@18.2.0 -> []\nzod -> []"
	if got != want {
		t.Fatalf("unexpected pretty string:\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestPrettyTree_WithSharedDependency(t *testing.T) {
	g := New()
	a := NewDependencyRef("a", "")
	b := NewDependencyRef("b", "")
	c := NewDependencyRef("c", "")

	for _, n := range []*Dependency{a, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(a.ID, b.ID); err != nil {
		t.Fatalf("add a->b: %v", err)
	}
	if err := g.AddEdge(c.ID, b.ID); err != nil {
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
	app := NewDependencyRef("app", "")
	a := NewDependencyRef("a", "")
	b := NewDependencyRef("b", "")

	for _, n := range []*Dependency{app, a, b} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	for _, edge := range [][2]string{{app.ID, a.ID}, {a.ID, b.ID}, {b.ID, a.ID}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
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
	a := NewDependencyRef("a", "")
	b := NewDependencyRef("b", "")
	c := NewDependencyRef("c", "")

	for _, n := range []*Dependency{a, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(a.ID, b.ID); err != nil {
		t.Fatalf("add a->b: %v", err)
	}
	if err := g.AddEdge(c.ID, b.ID); err != nil {
		t.Fatalf("add c->b: %v", err)
	}

	if ok := g.RemoveNode(b.ID); !ok {
		t.Fatalf("remove b failed")
	}

	d := NewDependencyRef("d", "")
	if err := g.AddNode(d); err != nil {
		t.Fatalf("add d: %v", err)
	}
	if err := g.AddEdge(a.ID, d.ID); err != nil {
		t.Fatalf("add a->d: %v", err)
	}
	if err := g.AddEdge(c.ID, d.ID); err != nil {
		t.Fatalf("add c->d: %v", err)
	}

	if got := g.Size(); got != 3 {
		t.Fatalf("expected size 3, got %d", got)
	}
	deps, err := g.DirectDependencies(a.ID)
	if err != nil {
		t.Fatalf("direct dependencies(a): %v", err)
	}
	if len(deps) != 1 || deps[0].ID != d.ID {
		t.Fatalf("expected a to depend on d, got %#v", deps)
	}
}

func TestCompare_ClassifiesAddedRemovedAndUpdated(t *testing.T) {
	base := New()
	head := New()

	baseApp := NewDependencyRef("app", "1.0.0")
	baseKeep := NewDependency(Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "keep", Version: "1.0.0"}})
	baseRemove := NewDependency(Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "remove", Version: "1.0.0"}})
	baseUpdate := NewDependency(Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "update", Version: "1.0.0"}})
	headApp := NewDependencyRef("app", "1.0.0")
	headKeep := NewDependency(Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "keep", Version: "1.0.0"}})
	headAdd := NewDependency(Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "add", Version: "2.0.0"}})
	headUpdate := NewDependency(Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "update", Version: "2.0.0"}})

	for _, node := range []*Dependency{baseApp, baseKeep, baseRemove, baseUpdate} {
		if err := base.AddNode(node); err != nil {
			t.Fatalf("base.AddNode(%q): %v", node.ID, err)
		}
	}
	for _, node := range []*Dependency{headApp, headKeep, headAdd, headUpdate} {
		if err := head.AddNode(node); err != nil {
			t.Fatalf("head.AddNode(%q): %v", node.ID, err)
		}
	}

	diff := Compare(base, head)
	if got := idsOf(diff.Added); !slices.Equal(got, []string{"add@2.0.0"}) {
		t.Fatalf("unexpected added nodes: %#v", got)
	}
	if got := idsOf(diff.Removed); !slices.Equal(got, []string{"remove@1.0.0"}) {
		t.Fatalf("unexpected removed nodes: %#v", got)
	}
	if len(diff.Updated) != 1 {
		t.Fatalf("expected one updated node, got %#v", diff.Updated)
	}
	if diff.Updated[0].Before.ID != "update@1.0.0" || diff.Updated[0].After.ID != "update@2.0.0" {
		t.Fatalf("unexpected updated node: %#v", diff.Updated[0])
	}
}

func TestCompare_IgnoresSyntheticSubprojectRoots(t *testing.T) {
	base := New()
	head := New()
	for _, g := range []*Graph{base, head} {
		for _, node := range []*Dependency{
			NewDependencyRefWithID("subproject:npm:root", "root", ""),
			NewDependency(Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "shared", Version: "1.0.0"}}),
		} {
			if err := g.AddNode(node); err != nil {
				t.Fatalf("AddNode(%q): %v", node.ID, err)
			}
		}
	}

	diff := Compare(base, head)
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Updated) != 0 {
		t.Fatalf("expected empty diff, got %#v", diff)
	}
}

func TestCompareIgnoresManifestAndRootNodes(t *testing.T) {
	base := New()
	head := New()
	for _, node := range []*Dependency{
		NewDependencyWithID("pkg:generic/root", Dependency{Coordinates: Coordinates{Name: "root", PURL: "pkg:generic/root"}}),
		NewDependencyWithID("pkg:generic/requirements.txt", Dependency{Coordinates: Coordinates{Name: "requirements.txt", PURL: "pkg:generic/requirements.txt"}}),
		NewDependencyWithID("pkg:npm/react@18.2.0", Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Name: "react", Version: "18.2.0", PURL: "pkg:npm/react@18.2.0"}}),
	} {
		if err := head.AddNode(node); err != nil {
			t.Fatalf("head add node %q: %v", node.ID, err)
		}
	}
	if err := base.AddNode(NewDependencyWithID("pkg:npm/react@18.2.0", Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Name: "react", Version: "18.2.0", PURL: "pkg:npm/react@18.2.0"}})); err != nil {
		t.Fatalf("base add node: %v", err)
	}

	diff := Compare(base, head)
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Updated) != 0 {
		t.Fatalf("expected manifest/root nodes to be ignored, got %#v", diff)
	}
}

func TestCompareIgnoresApplicationNodes(t *testing.T) {
	base := New()
	head := New()
	if err := head.AddNode(NewDependencyWithID("pkg:npm/demo@1.0.0", Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Name: "demo", Version: "1.0.0", Type: PackageTypeApplication, PURL: "pkg:npm/demo@1.0.0"}})); err != nil {
		t.Fatalf("head add application: %v", err)
	}

	diff := Compare(base, head)
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Updated) != 0 {
		t.Fatalf("expected application node to be ignored, got %#v", diff)
	}
}

func TestPackageHelpers(t *testing.T) {
	pkg := &Package{Coordinates: Coordinates{PURL: "pkg:generic/acme/demo@1.0.0",
		Org:     "acme",
		Name:    "demo",
		Version: "1.0.0"}, Licenses: []PackageLicense{
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

func idsOf(nodes []*Dependency) []string {
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
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
	if got := idsOf(path.Nodes); !slices.Equal(got, want) {
		t.Fatalf("expected path %v, got %v", want, got)
	}
}
