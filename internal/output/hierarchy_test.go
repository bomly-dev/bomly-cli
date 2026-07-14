package output

import (
	"reflect"
	"testing"
)

func TestClassifyManifest(t *testing.T) {
	cases := []struct {
		name           string
		subproject     string
		path           string
		wantSubproject string
		wantModule     string
	}{
		{"root manifest", "", "package-lock.json", ".", ""},
		{"root manifest dot subproject", ".", "pom.xml", ".", ""},
		{"module under root", ".", "apps/web/package.json", ".", "apps/web"},
		{"deep module under root", "", "crates/tools/cli/Cargo.toml", ".", "crates/tools/cli"},
		{"subproject manifest", "services/api", "services/api/pom.xml", "services/api", ""},
		{"module under subproject", "services/api", "services/api/module-a/pom.xml", "services/api", "services/api/module-a"},
		{"manifest outside subproject attaches directly", "services/api", "pom.xml", "services/api", ""},
		{"windows separators", `services\api`, `services\api\module-a\pom.xml`, "services/api", "services/api/module-a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotSubproject, gotModule := ClassifyManifest(tc.subproject, tc.path)
			if gotSubproject != tc.wantSubproject || gotModule != tc.wantModule {
				t.Fatalf("ClassifyManifest(%q, %q) = (%q, %q), want (%q, %q)",
					tc.subproject, tc.path, gotSubproject, gotModule, tc.wantSubproject, tc.wantModule)
			}
		})
	}
}

func TestBuildHierarchySingleRootHasNoGroups(t *testing.T) {
	hierarchy := BuildHierarchy([]ScanManifest{
		{Path: "package-lock.json", Subproject: "."},
		{Path: "go.mod", Subproject: "."},
	})
	if hierarchy.HasGroups() {
		t.Fatalf("expected flat hierarchy, got children %#v", hierarchy.Children)
	}
	if got, want := hierarchy.ManifestIndexes, []int{0, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected root manifests %v, got %v", want, got)
	}
}

func TestBuildHierarchyRootLockfileWithModuleSiblings(t *testing.T) {
	hierarchy := BuildHierarchy([]ScanManifest{
		{Path: "package-lock.json", Subproject: "."},
		{Path: "apps/web/package.json", Subproject: "."},
		{Path: "packages/lib/package.json", Subproject: "."},
	})
	if got, want := hierarchy.ManifestIndexes, []int{0}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected root lockfile attached to project, got %v", got)
	}
	if len(hierarchy.Children) != 2 {
		t.Fatalf("expected two module siblings, got %#v", hierarchy.Children)
	}
	for i, want := range []struct{ dir, label string }{{"apps/web", "apps/web"}, {"packages/lib", "packages/lib"}} {
		child := hierarchy.Children[i]
		if child.Kind != ManifestNodeModule || child.Dir != want.dir || child.Label != want.label {
			t.Fatalf("child %d = %#v, want module %q", i, child, want.dir)
		}
	}
}

func TestBuildHierarchySubprojectsAndModules(t *testing.T) {
	hierarchy := BuildHierarchy([]ScanManifest{
		{Path: "requirements.txt", Subproject: "."},
		{Path: "apps/web/package.json", Subproject: "."},
		{Path: "services/api/pom.xml", Subproject: "services/api"},
		{Path: "services/api/module-a/pom.xml", Subproject: "services/api"},
		{Path: "harness/requirements.txt", Subproject: "harness"},
	})

	if got, want := hierarchy.ManifestIndexes, []int{0}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected root manifest indexes %v, got %v", want, got)
	}
	// Modules first, then subprojects, each sorted by dir.
	kinds := make([]ManifestNodeKind, 0, len(hierarchy.Children))
	dirs := make([]string, 0, len(hierarchy.Children))
	for _, child := range hierarchy.Children {
		kinds = append(kinds, child.Kind)
		dirs = append(dirs, child.Dir)
	}
	wantKinds := []ManifestNodeKind{ManifestNodeModule, ManifestNodeSubproject, ManifestNodeSubproject}
	wantDirs := []string{"apps/web", "harness", "services/api"}
	if !reflect.DeepEqual(kinds, wantKinds) || !reflect.DeepEqual(dirs, wantDirs) {
		t.Fatalf("children = %v %v, want %v %v", kinds, dirs, wantKinds, wantDirs)
	}

	api := hierarchy.Children[2]
	if got, want := api.ManifestIndexes, []int{2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected api manifests %v, got %v", want, got)
	}
	if len(api.Children) != 1 || api.Children[0].Kind != ManifestNodeModule || api.Children[0].Dir != "services/api/module-a" {
		t.Fatalf("expected module child under services/api, got %#v", api.Children)
	}
	if got, want := api.Children[0].Label, "module-a"; got != want {
		t.Fatalf("module label = %q, want %q (relative to subproject)", got, want)
	}
	if got, want := api.Children[0].ManifestIndexes, []int{3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected module manifests %v, got %v", want, got)
	}

	if got := hierarchy.CountKind(ManifestNodeSubproject); got != 2 {
		t.Fatalf("CountKind(subproject) = %d, want 2", got)
	}
	if got := hierarchy.CountKind(ManifestNodeModule); got != 2 {
		t.Fatalf("CountKind(module) = %d, want 2", got)
	}
	if !hierarchy.HasGroups() {
		t.Fatal("expected HasGroups to be true")
	}
}
