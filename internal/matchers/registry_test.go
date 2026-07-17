package matchers

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestRegistryPackagesForGraphSkipsFirstPartyNodes(t *testing.T) {
	graph := sdk.New()
	app := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, PackageManager: sdk.PackageManagerMaven,
		Org: "com.acme", Name: "my-module", Version: "1.0.0",
		Type: sdk.PackageTypeApplication, FirstParty: true, PURL: "pkg:maven/com.acme/my-module@1.0.0",
	}})
	manifest := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Name: "pom.xml", Type: sdk.PackageTypeManifest,
	}})
	pkg := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, PackageManager: sdk.PackageManagerMaven,
		Org: "com.guava", Name: "guava", Version: "31.0",
		PURL: "pkg:maven/com.guava/guava@31.0",
	}})
	for _, node := range []*sdk.Dependency{app, manifest, pkg} {
		if err := graph.AddNode(node); err != nil {
			t.Fatalf("add node %q: %v", node.Name, err)
		}
	}

	registry := sdk.NewPackageRegistry()
	packages := RegistryPackagesForGraph(graph, registry, nil)

	if len(packages) != 1 || packages[0].Name != "guava" {
		t.Fatalf("expected only the third-party package to be enrichable, got %#v", packages)
	}
	if _, ok := registry.Get("pkg:maven/com.acme/my-module@1.0.0"); ok {
		t.Fatal("first-party application package must not be seeded for enrichment")
	}
	if app.PackageRef != "" {
		t.Fatalf("first-party node must not be linked to an enrichment package, got PackageRef %q", app.PackageRef)
	}
}

// TestRegistryPackagesForGraphKeepsImportedApplicationComponents locks in
// that ownership is the FirstParty marker, never the component type: an
// application-typed component imported from an SBOM document is an artifact
// kind (CycloneDX/SPDX), not proof it belongs to the scanned project, and
// must keep flowing to enrichment.
func TestRegistryPackagesForGraphKeepsImportedApplicationComponents(t *testing.T) {
	doc := &sbom.Document{Components: []sbom.Component{{
		ID: "pkg:npm/bundled-app@2.0.0", Name: "bundled-app", Version: "2.0.0",
		PURL: "pkg:npm/bundled-app@2.0.0", Ecosystem: "npm", Type: "application",
	}}}
	graph, err := sbom.ToGraph(doc)
	if err != nil {
		t.Fatalf("ToGraph() error = %v", err)
	}

	registry := sdk.NewPackageRegistry()
	packages := RegistryPackagesForGraph(graph, registry, nil)
	if len(packages) != 1 || packages[0].Name != "bundled-app" {
		t.Fatalf("expected the imported application component to stay enrichable, got %#v", packages)
	}
}

func TestRegistryPackagesForGraphTargetRespectsFirstParty(t *testing.T) {
	graph := sdk.New()
	app := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, PackageManager: sdk.PackageManagerNPM,
		Name: "my-app", Version: "1.0.0",
		Type: sdk.PackageTypeApplication, FirstParty: true, PURL: "pkg:npm/my-app@1.0.0",
	}})
	if err := graph.AddNode(app); err != nil {
		t.Fatalf("add node: %v", err)
	}

	registry := sdk.NewPackageRegistry()
	if packages := RegistryPackagesForGraph(graph, registry, app); len(packages) != 0 {
		t.Fatalf("expected first-party target to yield no enrichable packages, got %#v", packages)
	}
}
