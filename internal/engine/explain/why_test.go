package explain

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestFindWhy_MarksCyclicPaths(t *testing.T) {
	deps := sdk.New()
	app := sdk.NewDependencyRef("app", "")
	b := sdk.NewDependencyRef("b", "")
	c := sdk.NewDependencyRef("c", "")

	for _, pkg := range []*sdk.Dependency{app, b, c} {
		if err := deps.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	for _, edge := range [][2]string{{app.ID, b.ID}, {b.ID, c.ID}, {c.ID, b.ID}} {
		if err := deps.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add dependency %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	target, paths, err := FindWhy(deps, b.ID)
	if err != nil {
		t.Fatalf("FindWhy(): %v", err)
	}
	if target.ID != b.ID {
		t.Fatalf("expected target %q, got %q", b.ID, target.ID)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %#v", paths)
	}

	if paths[0].Cyclic {
		t.Fatalf("expected first path to be non-cyclic")
	}
	assertPathIDs(t, paths[0], []string{"app", "b"})

	if !paths[1].Cyclic {
		t.Fatalf("expected second path to be cyclic")
	}
	if paths[1].CycleTo != b.ID {
		t.Fatalf("expected cycle to %q, got %q", b.ID, paths[1].CycleTo)
	}
	assertPathIDs(t, paths[1], []string{"app", "b", "c", "b"})
}

func TestFindWhy_ReturnsAllPathsInDeterministicOrder(t *testing.T) {
	deps := sdk.New()
	nodes := []*sdk.Dependency{
		sdk.NewDependencyRef("root-b", ""),
		sdk.NewDependencyRef("middle", ""),
		sdk.NewDependencyRef("target", ""),
		sdk.NewDependencyRef("root-a", ""),
	}
	for _, pkg := range nodes {
		if err := deps.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	for _, edge := range [][2]string{
		{"root-b", "middle"},
		{"middle", "target"},
		{"root-a", "target"},
		{"root-b", "target"},
	} {
		if err := deps.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add dependency %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	_, paths, err := FindWhy(deps, "target")
	if err != nil {
		t.Fatalf("FindWhy(): %v", err)
	}
	if len(paths) != 3 {
		t.Fatalf("expected every root-to-target path, got %#v", paths)
	}
	assertPathIDs(t, paths[0], []string{"root-a", "target"})
	assertPathIDs(t, paths[1], []string{"root-b", "middle", "target"})
	assertPathIDs(t, paths[2], []string{"root-b", "target"})
}

func assertPathIDs(t *testing.T, path Path, want []string) {
	t.Helper()
	if len(path.Packages) != len(want) {
		t.Fatalf("expected %d packages, got %#v", len(want), path.Packages)
	}
	for i, pkg := range path.Packages {
		if pkg.ID != want[i] {
			t.Fatalf("expected package %d to be %q, got %q", i, want[i], pkg.ID)
		}
	}
}
