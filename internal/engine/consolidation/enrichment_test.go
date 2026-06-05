package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestBuildPackageRegistry_DeduplicatesByPURLAndLinksDependencies(t *testing.T) {
	g := sdk.New()
	app := sdk.NewDependency(sdk.Dependency{Ecosystem: "npm", Name: "app", Version: "1.0.0", Type: "application"})
	libA := sdk.NewDependency(sdk.Dependency{Ecosystem: "npm", Name: "lib", Version: "1.2.3"})
	for _, node := range []*sdk.Dependency{app, libA} {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%q): %v", node.ID, err)
		}
	}
	if err := g.AddEdge(app.ID, libA.ID); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}

	consolidated := sdk.ConsolidatedGraph{
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{Graph: g}}},
	}

	registry := BuildPackageRegistry(consolidated)
	libPURL := sdk.CanonicalPackageURLFromDependency(libA)
	if libPURL == "" {
		t.Fatal("expected non-empty PURL for lib")
	}
	if _, ok := registry.Get(libPURL); !ok {
		t.Fatalf("expected registry to contain %q", libPURL)
	}
	if libA.PackageRef != libPURL {
		t.Errorf("expected dependency PackageRef %q, got %q", libPURL, libA.PackageRef)
	}
}

func TestBuildPackageRegistry_LiftsDetectionLicenses(t *testing.T) {
	g := sdk.New()
	lib := sdk.NewDependency(sdk.Dependency{Ecosystem: "npm", Name: "lib", Version: "1.2.3"})
	sdk.SetDetectionLicenses(lib, []sdk.PackageLicense{{Value: "MIT", Type: "declared"}})
	if err := g.AddNode(lib); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	consolidated := sdk.ConsolidatedGraph{
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{Graph: g}}},
	}
	registry := BuildPackageRegistry(consolidated)
	pkg, ok := registry.Get(sdk.CanonicalPackageURLFromDependency(lib))
	if !ok {
		t.Fatal("expected registry package for lib")
	}
	if len(pkg.Licenses) != 1 || pkg.Licenses[0].Value != "MIT" {
		t.Errorf("expected detection license lifted into registry, got %#v", pkg.Licenses)
	}
}
