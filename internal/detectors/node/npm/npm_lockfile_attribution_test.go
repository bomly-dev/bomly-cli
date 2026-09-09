package npm

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	sdk "github.com/bomly-dev/bomly-sdk"
)

// crossScopeFixtureDir is the workspace where one package is a direct
// development dependency of one member and a transitive runtime dependency of
// another — the case a node-level scope union and relationship scalar cannot
// express.
func crossScopeFixtureDir(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller path")
	}
	return filepath.Join(filepath.Dir(here), "..", "testdata", "lockfiles", "npm-v3-workspaces-cross-scope")
}

func locationsOf(t *testing.T, graph *sdk.Graph, want string) []sdk.PackageLocation {
	t.Helper()
	dep, ok := testnodes.FindDep(graph, want)
	if !ok {
		t.Fatalf("expected %q in graph", want)
	}
	return dep.Locations
}

func TestNPMLockfileWorkspaceRecordsOneLocationPerModuleUsage(t *testing.T) {
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: crossScopeFixtureDir(t)})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	var member *sdk.Graph
	for _, entry := range result.Graphs.Entries {
		if filepath.ToSlash(entry.Manifest.Path) == "apps/web/package.json" {
			member = entry.Graph
		}
	}
	if member == nil {
		t.Fatal("expected an apps/web member entry")
	}

	locations := locationsOf(t, member, "shared-tool@1.0.0")
	byRoot := map[string]sdk.PackageLocation{}
	for _, location := range locations {
		if _, duplicate := byRoot[location.ModuleRoot]; duplicate {
			t.Fatalf("two records for module root %q: %+v", location.ModuleRoot, locations)
		}
		byRoot[location.ModuleRoot] = location
	}

	web, ok := byRoot["apps/web"]
	if !ok {
		t.Fatalf("expected a record attributed to apps/web, got %+v", locations)
	}
	if web.Relationship != sdk.DependencyRelationshipDirect {
		t.Fatalf("apps/web declares shared-tool itself: want direct, got %q", web.Relationship)
	}
	if len(web.Scopes) != 1 || web.Scopes[0] != sdk.ScopeDevelopment {
		t.Fatalf("apps/web declares shared-tool under devDependencies: want [development], got %v", web.Scopes)
	}

	lib, ok := byRoot["packages/lib"]
	if !ok {
		t.Fatalf("expected a record attributed to packages/lib, got %+v", locations)
	}
	if lib.Relationship != sdk.DependencyRelationshipTransitive {
		t.Fatalf("packages/lib reaches shared-tool through runtime-dep: want transitive, got %q", lib.Relationship)
	}
	if len(lib.Scopes) != 1 || lib.Scopes[0] != sdk.ScopeRuntime {
		t.Fatalf("packages/lib reaches shared-tool at runtime: want [runtime], got %v", lib.Scopes)
	}

	if web.RealPath != lib.RealPath {
		t.Fatalf("both usages are the same lockfile site: %q vs %q", web.RealPath, lib.RealPath)
	}

	// The node-level summaries stay as they were: this change adds the
	// per-site record beside them rather than replacing them.
	dep, _ := testnodes.FindDep(member, "shared-tool@1.0.0")
	if len(dep.Scopes) != 2 {
		t.Fatalf("expected the node union to keep both scopes, got %v", dep.Scopes)
	}
}

func TestNPMLockfileWorkspaceAttributesEachMemberEntry(t *testing.T) {
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: workspacesFixtureDir(t)})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	shared := map[string]struct{}{}
	for _, entry := range result.Graphs.Entries {
		for _, dep := range entry.Graph.DependencyNodes() {
			for _, location := range dep.Locations {
				if location.ModuleRoot == "" {
					t.Fatalf("%s carries an unattributed location %+v", dep.NodeID(), location)
				}
				if testnodes.Is(dep, "shared-transitive@2.0.0") {
					shared[location.ModuleRoot] = struct{}{}
				}
			}
		}
	}
	if len(shared) != 2 {
		t.Fatalf("shared-transitive is used by both members: want 2 module roots, got %v", shared)
	}
	for _, want := range []string{"apps/web", "packages/lib"} {
		if _, ok := shared[want]; !ok {
			t.Fatalf("expected a record for module root %q, got %v", want, shared)
		}
	}
}
