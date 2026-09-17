package consolidation

import (
	"path"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
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
	result := func(subproject, root string, scope model.Scope, relationship model.DependencyRelationship) plugin.DetectionResult {
		g := model.New()
		pkg := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{
			Name: "left-pad", Version: "1.3.0", Ecosystem: model.EcosystemNPM, PURL: "pkg:npm/left-pad@1.3.0"}})
		pkg.Locations = []model.PackageLocation{{
			RealPath:     site,
			AccessPath:   site,
			Position:     &model.SourcePosition{File: site, Line: 42},
			ModuleRoot:   root,
			Scopes:       []model.Scope{scope},
			Relationship: relationship,
		}}
		if err := g.AddNode(pkg); err != nil {
			t.Fatal(err)
		}
		return plugin.DetectionResult{
			SubprojectInfo: plugin.Subproject{
				ExecutionTarget:         plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo"},
				RelativePath:            subproject,
				PrimaryDetector:         "pnpm-detector",
				DetectedPackageManagers: []model.PackageManager{model.PackageManagerPNPM},
				Ecosystem:               model.EcosystemNPM,
			},
			DetectorName: "pnpm-detector",
			Graphs:       model.SingleGraphContainer(g, model.ManifestMetadata{Path: subproject + "/" + site, Kind: "pnpm-lock.yaml"}),
		}
	}

	consolidated, err := ConsolidateGraphs([]plugin.DetectionResult{
		result("apps/one", "packages/a", model.ScopeRuntime, model.DependencyRelationshipDirect),
		result("apps/two", "packages/b", model.ScopeDevelopment, model.DependencyRelationshipTransitive),
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
	byRoot := map[string]model.PackageLocation{}
	for _, loc := range found[0].Locations {
		byRoot[path.Base(loc.ModuleRoot)] = loc
	}
	if len(byRoot) != 2 {
		t.Fatalf("locations = %+v, want one record per module root", found[0].Locations)
	}
	if a := byRoot["a"]; a.Relationship != model.DependencyRelationshipDirect || len(a.Scopes) != 1 || a.Scopes[0] != model.ScopeRuntime {
		t.Errorf("packages/a record = %+v, want runtime/direct", a)
	}
	if b := byRoot["b"]; b.Relationship != model.DependencyRelationshipTransitive || len(b.Scopes) != 1 || b.Scopes[0] != model.ScopeDevelopment {
		t.Errorf("packages/b record = %+v, want development/transitive", b)
	}
}
