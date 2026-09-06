package detectors

import (
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
)

func moduleNode(t *testing.T, manifest, name string) *sdk.ModuleNode {
	t.Helper()
	module, err := sdk.NewModuleNode(manifest, sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM,
		Name:      name,
		Version:   "1.0.0",
		Type:      sdk.PackageTypeApplication,
	})
	if err != nil {
		t.Fatalf("NewModuleNode(%q): %v", manifest, err)
	}
	return module
}

func dependencyNode(t *testing.T, name string, scopes ...sdk.Scope) *sdk.DependencyNode {
	t.Helper()
	dep, err := sdk.NewDependencyNodeFrom(sdk.DependencyNode{
		Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: name, Version: "1.0.0"},
		Scopes:      sdk.ScopesOf(scopes...),
		Locations: []sdk.PackageLocation{{
			RealPath:   "package-lock.json",
			AccessPath: "package-lock.json",
			Position:   &sdk.SourcePosition{File: "package-lock.json", Line: 7},
		}},
	})
	if err != nil {
		t.Fatalf("NewDependencyNodeFrom(%q): %v", name, err)
	}
	return dep
}

func addAll(t *testing.T, g *sdk.Graph, nodes ...sdk.GraphNode) {
	t.Helper()
	for _, node := range nodes {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%q): %v", node.NodeID(), err)
		}
	}
}

func edge(t *testing.T, g *sdk.Graph, from, to sdk.GraphNode) {
	t.Helper()
	if err := g.AddEdge(from.NodeID(), to.NodeID()); err != nil {
		t.Fatalf("AddEdge(%q -> %q): %v", from.NodeID(), to.NodeID(), err)
	}
}

func TestAttributedRecordsTheModuleRootAndDirectness(t *testing.T) {
	g := sdk.New()
	root := moduleNode(t, "package.json", "app")
	direct := dependencyNode(t, "direct", sdk.ScopeRuntime)
	transitive := dependencyNode(t, "transitive", sdk.ScopeRuntime)
	addAll(t, g, root, direct, transitive)
	edge(t, g, root, direct)
	edge(t, g, direct, transitive)

	Attributed(sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package.json"})})

	if got := direct.Locations[0].ModuleRoot; got != "." {
		t.Fatalf("module root = %q, want \".\" for the detector's own working directory", got)
	}
	if got := direct.Locations[0].Relationship; got != sdk.DependencyRelationshipDirect {
		t.Fatalf("relationship of a declared dependency = %q, want direct", got)
	}
	if got := transitive.Locations[0].Relationship; got != sdk.DependencyRelationshipTransitive {
		t.Fatalf("relationship of a dependency reached through another = %q, want transitive", got)
	}
	if got := direct.Locations[0].Scopes; len(got) != 1 || got[0] != sdk.ScopeRuntime {
		t.Fatalf("site scopes = %v, want [runtime] from the node's own scopes", got)
	}
	if len(direct.Locations) != 1 {
		t.Fatalf("one root and one site must stay one record, got %+v", direct.Locations)
	}
}

func TestAttributedNamesTheMemberDirectoryOfEachModule(t *testing.T) {
	g := sdk.New()
	member := moduleNode(t, "packages/lib/package.json", "lib")
	dep := dependencyNode(t, "dep", sdk.ScopeRuntime)
	addAll(t, g, member, dep)
	edge(t, g, member, dep)

	Attributed(sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "packages/lib/package.json"})})

	if got := dep.Locations[0].ModuleRoot; got != "packages/lib" {
		t.Fatalf("module root = %q, want the member directory packages/lib", got)
	}
	if got := member.Locations; len(got) != 0 {
		t.Fatalf("a module with no locations gains none, got %+v", got)
	}
}

func TestAttributedGivesEachModuleRootItsOwnRecord(t *testing.T) {
	shared := dependencyNode(t, "shared", sdk.ScopeRuntime, sdk.ScopeDevelopment)
	web := moduleNode(t, "apps/web/package.json", "web")
	lib := moduleNode(t, "packages/lib/package.json", "lib")
	middle := dependencyNode(t, "middle", sdk.ScopeRuntime)

	webGraph := sdk.New()
	addAll(t, webGraph, web, shared)
	edge(t, webGraph, web, shared)

	libGraph := sdk.New()
	addAll(t, libGraph, lib, middle, shared)
	edge(t, libGraph, lib, middle)
	edge(t, libGraph, middle, shared)

	Attributed(sdk.DetectionResult{Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{
		{Graph: webGraph, Manifest: sdk.ManifestMetadata{Path: "apps/web/package.json"}},
		{Graph: libGraph, Manifest: sdk.ManifestMetadata{Path: "packages/lib/package.json"}},
	}}},
		ModuleDeclarations{ModuleRoot: "apps/web", Scopes: map[string]sdk.Scope{"shared": sdk.ScopeDevelopment}},
		ModuleDeclarations{ModuleRoot: "packages/lib", Scopes: map[string]sdk.Scope{"middle": sdk.ScopeRuntime}},
	)

	byRoot := map[string]sdk.PackageLocation{}
	for _, location := range shared.Locations {
		byRoot[location.ModuleRoot] = location
	}
	if len(byRoot) != 2 {
		t.Fatalf("one site used by two modules is two usages, got %+v", shared.Locations)
	}
	if got := byRoot["apps/web"]; got.Relationship != sdk.DependencyRelationshipDirect ||
		len(got.Scopes) != 1 || got.Scopes[0] != sdk.ScopeDevelopment {
		t.Fatalf("apps/web declares shared as development: got %+v", got)
	}
	if got := byRoot["packages/lib"]; got.Relationship != sdk.DependencyRelationshipTransitive ||
		len(got.Scopes) != 1 || got.Scopes[0] != sdk.ScopeRuntime {
		t.Fatalf("packages/lib reaches shared at runtime through middle: got %+v", got)
	}
}

func TestAttributedLeavesScopesEmptyWhenTheUnionMixesModules(t *testing.T) {
	shared := dependencyNode(t, "shared", sdk.ScopeRuntime, sdk.ScopeDevelopment)
	web := moduleNode(t, "apps/web/package.json", "web")
	lib := moduleNode(t, "packages/lib/package.json", "lib")

	webGraph := sdk.New()
	addAll(t, webGraph, web, shared)
	edge(t, webGraph, web, shared)
	libGraph := sdk.New()
	addAll(t, libGraph, lib, shared)
	edge(t, libGraph, lib, shared)

	Attributed(sdk.DetectionResult{Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{
		{Graph: webGraph, Manifest: sdk.ManifestMetadata{Path: "apps/web/package.json"}},
		{Graph: libGraph, Manifest: sdk.ManifestMetadata{Path: "packages/lib/package.json"}},
	}}})

	if len(shared.Locations) != 2 {
		t.Fatalf("expected one record per module root, got %+v", shared.Locations)
	}
	for _, location := range shared.Locations {
		if len(location.Scopes) != 0 {
			t.Fatalf("with no declarations the union mixes both modules, so %q must claim no scope: %v",
				location.ModuleRoot, location.Scopes)
		}
	}
}

func TestAttributedIsIdempotentForOneRoot(t *testing.T) {
	g := sdk.New()
	root := moduleNode(t, "package.json", "app")
	dep := dependencyNode(t, "dep", sdk.ScopeRuntime)
	addAll(t, g, root, dep)
	edge(t, g, root, dep)
	result := sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package.json"})}

	Attributed(result)
	Attributed(result)

	if len(dep.Locations) != 1 {
		t.Fatalf("re-attributing one root must not add records, got %+v", dep.Locations)
	}
}

func TestAttributedLeavesSitesAloneWithoutAModuleRoot(t *testing.T) {
	g := sdk.New()
	dep := dependencyNode(t, "dep", sdk.ScopeRuntime)
	addAll(t, g, dep)

	Attributed(sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json"})})

	if got := dep.Locations[0].ModuleRoot; got != "" {
		t.Fatalf("nothing observed a module here, so the root must stay empty, got %q", got)
	}
	if got := dep.Locations[0].Relationship; got != "" {
		t.Fatalf("relationship = %q, want it left empty with no root to relate to", got)
	}
}

func TestAttributedKeepsAnUnrecoveredParentUnknown(t *testing.T) {
	g := sdk.New()
	root := moduleNode(t, "package.json", "app")
	orphan := dependencyNode(t, "orphan", sdk.ScopeRuntime)
	orphan.Relationship = sdk.DependencyRelationshipUnknown
	addAll(t, g, root, orphan)
	edge(t, g, root, orphan)

	Attributed(sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package.json"})})

	if got := orphan.Locations[0].Relationship; got != sdk.DependencyRelationshipUnknown {
		t.Fatalf("a component attached with an unknown parent stays unknown, got %q", got)
	}
}

func TestAttributedTerminatesOnACycle(t *testing.T) {
	g := sdk.New()
	root := moduleNode(t, "package.json", "app")
	first := dependencyNode(t, "first", sdk.ScopeRuntime)
	second := dependencyNode(t, "second", sdk.ScopeRuntime)
	addAll(t, g, root, first, second)
	edge(t, g, root, first)
	edge(t, g, first, second)
	edge(t, g, second, first)

	Attributed(sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package.json"})},
		ModuleDeclarations{ModuleRoot: ".", Scopes: map[string]sdk.Scope{"first": sdk.ScopeDevelopment}})

	if got := second.Locations[0].Scopes; len(got) != 1 || got[0] != sdk.ScopeDevelopment {
		t.Fatalf("scope propagated around the cycle = %v, want [development]", got)
	}
}

func TestAttributedLeavesAnotherModulesFileAlone(t *testing.T) {
	shared := dependencyNode(t, "shared", sdk.ScopeRuntime)
	shared.Locations = []sdk.PackageLocation{
		{RealPath: "apps/web/pom.xml", AccessPath: "apps/web/pom.xml"},
		{RealPath: "packages/lib/pom.xml", AccessPath: "packages/lib/pom.xml"},
	}
	web := moduleNode(t, "apps/web/pom.xml", "web")
	lib := moduleNode(t, "packages/lib/pom.xml", "lib")

	webGraph := sdk.New()
	addAll(t, webGraph, web, shared)
	edge(t, webGraph, web, shared)
	libGraph := sdk.New()
	addAll(t, libGraph, lib, shared)
	edge(t, libGraph, lib, shared)

	Attributed(sdk.DetectionResult{Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{
		{Graph: webGraph, Manifest: sdk.ManifestMetadata{Path: "apps/web/pom.xml"}},
		{Graph: libGraph, Manifest: sdk.ManifestMetadata{Path: "packages/lib/pom.xml"}},
	}}})

	if len(shared.Locations) != 2 {
		t.Fatalf("each module declares the package in its own file, so two records stay two: %+v", shared.Locations)
	}
	for _, location := range shared.Locations {
		if location.ModuleRoot+"/pom.xml" != location.RealPath {
			t.Fatalf("a file inside one module's directory must not be claimed by the other: %+v", location)
		}
	}
}
