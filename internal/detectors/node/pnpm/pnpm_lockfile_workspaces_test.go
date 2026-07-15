package pnpm

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func pnpmWorkspacesFixtureDir(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller path")
	}
	return filepath.Join(filepath.Dir(here), "..", "testdata", "lockfiles", "pnpm-v9-workspaces")
}

func TestPNPMLockfileImportersEmitPerModuleEntries(t *testing.T) {
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: pnpmWorkspacesFixtureDir(t)})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	entries := result.Graphs.Entries
	if len(entries) != 3 {
		t.Fatalf("expected root + 2 importer entries, got %d", len(entries))
	}
	paths := map[string]sdk.GraphEntry{}
	for _, entry := range entries {
		paths[filepath.ToSlash(entry.Manifest.Path)] = entry
	}
	web, ok := paths["apps/web/package.json"]
	if !ok {
		t.Fatalf("expected apps/web/package.json entry, got %v", paths)
	}
	if _, ok := paths["packages/lib/package.json"]; !ok {
		t.Fatalf("expected packages/lib/package.json entry, got %v", paths)
	}

	for _, want := range []string{"web@0.2.0", "lib@1.0.0", "shared-transitive@2.0.0", "member-dev-tool@3.1.0"} {
		if _, ok := web.Graph.Node(want); !ok {
			t.Fatalf("expected %q in web importer graph", want)
		}
	}
	if _, ok := web.Graph.Node("lodash@4.17.21"); ok {
		t.Fatal("web importer graph must not contain the root-only dependency lodash")
	}

	root := entries[0]
	if _, ok := root.Graph.Node("lodash@4.17.21"); !ok {
		t.Fatal("expected lodash in root entry graph")
	}
	if _, ok := root.Graph.Node("web@0.2.0"); ok {
		t.Fatal("root entry graph must not contain workspace members")
	}
}

func TestPNPMLockfileWorkspaceLinkDependenciesResolveToMembers(t *testing.T) {
	graphs, err := depGraphFromPNPMLockfile(pnpmWorkspacesFixtureDir(t))
	if err != nil {
		t.Fatalf("depGraphFromPNPMLockfile() error = %v", err)
	}
	deps, err := graphs.graph.DirectDependencies("web@0.2.0")
	if err != nil {
		t.Fatalf("DirectDependencies(web) error = %v", err)
	}
	found := false
	for _, dep := range deps {
		if dep.ID == "lib@1.0.0" {
			found = true
			if dep.Type != sdk.PackageTypeApplication {
				t.Fatalf("expected member target to be an application, got %q", dep.Type)
			}
		}
	}
	if !found {
		ids := make([]string, 0, len(deps))
		for _, dep := range deps {
			ids = append(ids, dep.ID)
		}
		t.Fatalf("expected web -> lib@1.0.0 workspace link edge, got %v", ids)
	}
}

func TestPNPMLockfileSingleImporterStillSingleEntry(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller path")
	}
	dir := filepath.Join(filepath.Dir(here), "..", "testdata", "lockfiles", "pnpm-v9")
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if len(result.Graphs.Entries) != 1 {
		t.Fatalf("expected single entry for single-importer lockfile, got %d", len(result.Graphs.Entries))
	}
}
