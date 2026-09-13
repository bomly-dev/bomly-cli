package consolidation

import (
	"path"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

// TestConsolidateGraphsKeepsEachModuleRootsRecordOfOneSite pins, from the CLI
// side, the case internal/detectors/attribution.go used to document as lost:
// two detection results holding distinct node instances of one package, each
// carrying one module root's record of the same declaration site. Before
// bomly-sdk v0.11.0 the fold keyed a location on its paths and position only,
// so the second root's record -- with its scope and relationship -- was
// dropped as a duplicate (bomly-dev/bomly-sdk#73). The usage unit is (module
// root, declaration site), and both usages survive consolidation.
func TestConsolidateGraphsKeepsEachModuleRootsRecordOfOneSite(t *testing.T) {
	const site = "pnpm-lock.yaml"
	result := func(subproject, root string, scope sdk.Scope, relationship sdk.DependencyRelationship) sdk.DetectionResult {
		g := sdk.New()
		pkg := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
			Name: "left-pad", Version: "1.3.0", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/left-pad@1.3.0"}})
		pkg.Locations = []sdk.PackageLocation{{
			RealPath:     site,
			AccessPath:   site,
			Position:     &sdk.SourcePosition{File: site, Line: 42},
			ModuleRoot:   root,
			Scopes:       []sdk.Scope{scope},
			Relationship: relationship,
		}}
		if err := g.AddNode(pkg); err != nil {
			t.Fatal(err)
		}
		return sdk.DetectionResult{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
				RelativePath:            subproject,
				PrimaryDetector:         "pnpm-detector",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerPNPM},
				Ecosystem:               sdk.EcosystemNPM,
			},
			DetectorName: "pnpm-detector",
			Graphs:       sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: subproject + "/" + site, Kind: "pnpm-lock.yaml"}),
		}
	}

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		result("apps/one", "packages/a", sdk.ScopeRuntime, sdk.DependencyRelationshipDirect),
		result("apps/two", "packages/b", sdk.ScopeDevelopment, sdk.DependencyRelationshipTransitive),
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	merged, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	found := nodesNamed(merged, "left-pad")
	if len(found) != 1 {
		t.Fatalf("left-pad nodes = %d, want one node per identity", len(found))
	}
	// Keyed by the root's last segment: whether consolidation rebased the
	// root into repository coordinates is not what this test is about.
	byRoot := map[string]sdk.PackageLocation{}
	for _, loc := range found[0].Locations {
		byRoot[path.Base(loc.ModuleRoot)] = loc
	}
	if len(byRoot) != 2 {
		t.Fatalf("locations = %+v, want one record per module root", found[0].Locations)
	}
	if a := byRoot["a"]; a.Relationship != sdk.DependencyRelationshipDirect || len(a.Scopes) != 1 || a.Scopes[0] != sdk.ScopeRuntime {
		t.Errorf("packages/a record = %+v, want runtime/direct", a)
	}
	if b := byRoot["b"]; b.Relationship != sdk.DependencyRelationshipTransitive || len(b.Scopes) != 1 || b.Scopes[0] != sdk.ScopeDevelopment {
		t.Errorf("packages/b record = %+v, want development/transitive", b)
	}
}
