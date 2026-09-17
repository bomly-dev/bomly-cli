package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestBuildPackageRegistry_DeduplicatesByPURLAndLinksDependencies(t *testing.T) {
	g := model.New()
	app := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "npm", Name: "app", Version: "1.0.0", Type: model.PackageTypeApplication}})
	libA := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "npm", Name: "lib", Version: "1.2.3"}})
	for _, node := range []*model.DependencyNode{app, libA} {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%q): %v", node.NodeID(), err)
		}
	}
	if err := g.AddEdge(app.NodeID(), libA.NodeID()); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}

	consolidated := plugin.ConsolidatedGraph{
		Graphs: &model.GraphContainer{Entries: []model.GraphEntry{{Graph: g}}},
	}

	registry := BuildPackageRegistry(consolidated)
	libPURL := libA.NodeID()
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
	g := model.New()
	lib := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "npm", Name: "lib", Version: "1.2.3"}})
	model.SetDetectionLicenses(lib, []model.PackageLicense{{Value: "MIT", Type: "declared"}})
	if err := g.AddNode(lib); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	consolidated := plugin.ConsolidatedGraph{
		Graphs: &model.GraphContainer{Entries: []model.GraphEntry{{Graph: g}}},
	}
	registry := BuildPackageRegistry(consolidated)
	pkg, ok := registry.Get(lib.NodeID())
	if !ok {
		t.Fatal("expected registry package for lib")
	}
	if len(pkg.Licenses) != 1 || pkg.Licenses[0].Value != "MIT" {
		t.Errorf("expected detection license lifted into registry, got %#v", pkg.Licenses)
	}
}
