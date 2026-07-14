package npm

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func workspacesFixtureDir(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller path")
	}
	return filepath.Join(filepath.Dir(here), "..", "testdata", "lockfiles", "npm-v3-workspaces")
}

func TestNPMLockfileWorkspacesEmitsPerModuleEntries(t *testing.T) {
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: workspacesFixtureDir(t)})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	entries := result.Graphs.Entries
	if len(entries) != 3 {
		t.Fatalf("expected root + 2 member entries, got %d", len(entries))
	}

	paths := map[string]sdk.GraphEntry{}
	for _, entry := range entries {
		paths[filepath.ToSlash(entry.Manifest.Path)] = entry
	}
	web, ok := paths["apps/web/package.json"]
	if !ok {
		t.Fatalf("expected apps/web/package.json entry, got %v", keysOf(paths))
	}
	if web.Manifest.Kind != sdk.ManifestKind("package.json") {
		t.Fatalf("expected package.json kind for member, got %q", web.Manifest.Kind)
	}
	lib, ok := paths["packages/lib/package.json"]
	if !ok {
		t.Fatalf("expected packages/lib/package.json entry, got %v", keysOf(paths))
	}

	// The web member reaches its own deps, the lib member (a workspace link
	// dependency), and lib's transitive dep — but never the root's lodash.
	for _, want := range []string{"web@0.2.0", "lib@1.0.0", "shared-transitive@2.0.0", "member-dev-tool@3.1.0"} {
		if _, ok := web.Graph.Node(want); !ok {
			t.Fatalf("expected %q in web member graph, nodes missing", want)
		}
	}
	if _, ok := web.Graph.Node("lodash@4.17.21"); ok {
		t.Fatal("web member graph must not contain the root-only dependency lodash")
	}

	// The lib member sees only itself + shared transitive.
	if lib.Graph.Size() != 2 {
		t.Fatalf("expected 2 nodes in lib member graph, got %d", lib.Graph.Size())
	}

	// The root entry carries the root node and its own deps only.
	root := entries[0]
	if _, ok := root.Graph.Node("lodash@4.17.21"); !ok {
		t.Fatal("expected lodash in root entry graph")
	}
	if _, ok := root.Graph.Node("web@0.2.0"); ok {
		t.Fatal("root entry graph must not contain workspace members")
	}
}

func TestNPMLockfileWorkspaceLinkEntriesDoNotDuplicateNodes(t *testing.T) {
	graphs, err := depGraphFromNPMLockfile(workspacesFixtureDir(t))
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile() error = %v", err)
	}
	// The link alias node_modules/lib must resolve to the member node, not a
	// synthetic versionless "lib" package.
	if _, ok := graphs.graph.Node("lib"); ok {
		t.Fatal("unexpected versionless link ghost node for lib")
	}
	member, ok := graphs.graph.Node("lib@1.0.0")
	if !ok {
		t.Fatal("expected lib member node")
	}
	if member.Type != sdk.PackageTypeApplication {
		t.Fatalf("expected member node to be an application, got %q", member.Type)
	}
	// web depends on lib via the workspace link; the edge must target the member.
	deps, err := graphs.graph.DirectDependencies("web@0.2.0")
	if err != nil {
		t.Fatalf("DirectDependencies(web) error = %v", err)
	}
	found := false
	for _, dep := range deps {
		if dep.ID == "lib@1.0.0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected web -> lib@1.0.0 edge, got %v", depIDs(deps))
	}
}

func TestNPMLockfileWorkspaceMemberDevDependenciesScoped(t *testing.T) {
	graphs, err := depGraphFromNPMLockfile(workspacesFixtureDir(t))
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile() error = %v", err)
	}
	devDep, ok := graphs.graph.Node("member-dev-tool@3.1.0")
	if !ok {
		t.Fatal("expected member devDependency in graph")
	}
	hasDev := false
	for _, scope := range devDep.Scopes {
		if scope == sdk.ScopeDevelopment {
			hasDev = true
		}
	}
	if !hasDev {
		t.Fatalf("expected development scope on member dev dependency, got %v", devDep.Scopes)
	}
}

func TestNPMLockfileSingleProjectStillSingleEntry(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller path")
	}
	dir := filepath.Join(filepath.Dir(here), "..", "testdata", "lockfiles", "npm-v3")
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if len(result.Graphs.Entries) != 1 {
		t.Fatalf("expected single entry for non-workspace lockfile, got %d", len(result.Graphs.Entries))
	}
}

func keysOf(m map[string]sdk.GraphEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func depIDs(deps []*sdk.Dependency) []string {
	ids := make([]string, 0, len(deps))
	for _, dep := range deps {
		ids = append(ids, dep.ID)
	}
	return ids
}
