package sdk

import "testing"

func TestFilterGraphByScope(t *testing.T) {
	depsGraph := New()
	root := NewDependency(Dependency{Name: "app", Version: "1.0.0"})
	runtimeDep := NewDependency(Dependency{Name: "react", Version: "18.2.0", Scopes: ScopesOf(ScopeRuntime)})
	devDep := NewDependency(Dependency{Name: "vitest", Version: "2.0.0", Scopes: ScopesOf(ScopeDevelopment)})
	for _, pkg := range []*Dependency{root, runtimeDep, devDep} {
		if err := depsGraph.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	if err := depsGraph.AddEdge(root.ID, runtimeDep.ID); err != nil {
		t.Fatalf("add runtime dependency: %v", err)
	}
	if err := depsGraph.AddEdge(root.ID, devDep.ID); err != nil {
		t.Fatalf("add development dependency: %v", err)
	}

	filtered, err := FilterGraphByScope(depsGraph, ScopeRuntime)
	if err != nil {
		t.Fatalf("FilterGraphByScope() error = %v", err)
	}
	if filtered.Size() != 2 {
		t.Fatalf("expected 2 packages after runtime filter, got %d", filtered.Size())
	}
	if _, ok := filtered.Node(runtimeDep.ID); !ok {
		t.Fatal("expected runtime dependency to be kept")
	}
	if _, ok := filtered.Node(devDep.ID); ok {
		t.Fatal("expected development dependency to be removed")
	}
}

func TestFilterDetectionResultByScope_FiltersEntryPackages(t *testing.T) {
	depsGraph := New()
	root := NewDependency(Dependency{Name: "app", Version: "1.0.0"})
	runtimeDep := NewDependency(Dependency{Ecosystem: "npm", Name: "react", Version: "18.2.0", Scopes: ScopesOf(ScopeRuntime)})
	devDep := NewDependency(Dependency{Ecosystem: "npm", Name: "vitest", Version: "2.0.0", Scopes: ScopesOf(ScopeDevelopment)})
	for _, pkg := range []*Dependency{root, runtimeDep, devDep} {
		if err := depsGraph.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	if err := depsGraph.AddEdge(root.ID, runtimeDep.ID); err != nil {
		t.Fatalf("add runtime dependency: %v", err)
	}
	if err := depsGraph.AddEdge(root.ID, devDep.ID); err != nil {
		t.Fatalf("add development dependency: %v", err)
	}

	result := DetectionResult{
		Graphs: &GraphContainer{Entries: []GraphEntry{{
			Graph:    depsGraph,
			Manifest: ManifestMetadata{Path: "package-lock.json"},
			Packages: []*Package{
				{PURL: BuildPackageURL("npm", "", "react", "18.2.0")},
				{PURL: BuildPackageURL("npm", "", "vitest", "2.0.0")},
			},
		}}},
	}

	filtered, err := FilterDetectionResultByScope(result, ScopeRuntime)
	if err != nil {
		t.Fatalf("FilterDetectionResultByScope() error = %v", err)
	}
	entry := filtered.Graphs.Entries[0]
	if len(entry.Packages) != 1 || entry.Packages[0].PURL != BuildPackageURL("npm", "", "react", "18.2.0") {
		t.Fatalf("expected only runtime package facts, got %#v", entry.Packages)
	}
}

func TestFilterDetectionResultByScope_RepresentativeParserOutputs(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		manifest  string
	}{
		{"npm lockfile", "npm", "package-lock.json"},
		{"pnpm lockfile", "npm", "pnpm-lock.yaml"},
		{"yarn lockfile", "npm", "yarn.lock"},
		{"composer lockfile", "packagist", "composer.lock"},
		{"bundler lockfile", "rubygems", "Gemfile.lock"},
		{"nuget lockfile", "nuget", "packages.lock.json"},
		{"pub lockfile", "pub", "pubspec.lock"},
		{"mix lockfile", "hex", "mix.lock"},
		{"conan manifest", "conan", "conanfile.txt"},
		{"cocoapods lockfile", "cocoapods", "Podfile.lock"},
		{"sbt lockfile", "maven", "build.sbt"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectionResult{
				Graphs: &GraphContainer{Entries: []GraphEntry{{
					Graph:    representativeScopedGraph(t, tt.ecosystem),
					Manifest: ManifestMetadata{Path: tt.manifest},
				}}},
			}
			filtered, err := FilterDetectionResultByScope(result, ScopeRuntime)
			if err != nil {
				t.Fatalf("FilterDetectionResultByScope() error = %v", err)
			}
			graph := filtered.Graphs.Entries[0].Graph
			if _, ok := graph.Node(tt.ecosystem + "-runtime@1.0.0"); !ok {
				t.Fatalf("expected runtime dependency for %s: %s", tt.name, graph.PrettyString())
			}
			if _, ok := graph.Node(tt.ecosystem + "-dev@1.0.0"); ok {
				t.Fatalf("expected development dependency to be filtered for %s: %s", tt.name, graph.PrettyString())
			}
		})
	}
}

func representativeScopedGraph(t *testing.T, ecosystem string) *Graph {
	t.Helper()
	graph := New()
	root := NewDependency(Dependency{Ecosystem: ecosystem, Name: ecosystem + "-app", Version: "1.0.0"})
	runtimeDep := NewDependency(Dependency{Ecosystem: ecosystem, Name: ecosystem + "-runtime", Version: "1.0.0", Scopes: ScopesOf(ScopeRuntime)})
	devDep := NewDependency(Dependency{Ecosystem: ecosystem, Name: ecosystem + "-dev", Version: "1.0.0", Scopes: ScopesOf(ScopeDevelopment)})
	for _, dep := range []*Dependency{root, runtimeDep, devDep} {
		if err := graph.AddNode(dep); err != nil {
			t.Fatalf("add %q: %v", dep.ID, err)
		}
	}
	if err := graph.AddEdge(root.ID, runtimeDep.ID); err != nil {
		t.Fatalf("add runtime edge: %v", err)
	}
	if err := graph.AddEdge(root.ID, devDep.ID); err != nil {
		t.Fatalf("add development edge: %v", err)
	}
	return graph
}
