package remediation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestDerivePackageRemediation(t *testing.T) {
	tests := []struct {
		name            string
		currentVersion  string
		vulnerabilities []model.Vulnerability
		want            *model.PackageRemediation
	}{
		{
			name: "no vulnerabilities",
		},
		{
			name: "one fixed in version",
			vulnerabilities: []model.Vulnerability{{
				FixState: model.FixStateFixed,
				FixedIn:  "1.2.0",
			}},
			want: &model.PackageRemediation{
				Status:             model.PackageRemediationComplete,
				RecommendedVersion: "1.2.0",
			},
		},
		{
			name: "uses preferred source and highest required version",
			vulnerabilities: []model.Vulnerability{
				{
					FixedIn:       "1.4.0",
					FixAvailable:  []model.FixAvailable{{Version: "9.0.0"}},
					FixedVersions: []string{"8.0.0"},
				},
				{
					FixAvailable: []model.FixAvailable{
						{Version: "2.1.0"},
						{Version: "2.0.0"},
					},
					FixedVersions: []string{"7.0.0"},
				},
				{
					FixedVersions: []string{"1.5.0", "1.6.0"},
				},
			},
			want: &model.PackageRemediation{
				Status:             model.PackageRemediationComplete,
				RecommendedVersion: "2.0.0",
			},
		},
		{
			name:           "selects fix from current release line",
			currentVersion: "1.2.5",
			vulnerabilities: []model.Vulnerability{{
				FixedVersions: []string{"0.2.4", "1.2.6"},
			}},
			want: &model.PackageRemediation{
				Status:             model.PackageRemediationComplete,
				RecommendedVersion: "1.2.6",
			},
		},
		{
			name:           "does not recommend a downgrade",
			currentVersion: "1.2.5",
			vulnerabilities: []model.Vulnerability{{
				FixedVersions: []string{"0.2.4", "1.2.4"},
			}},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
		{
			name:           "does not recommend installed version",
			currentVersion: "1.2.5",
			vulnerabilities: []model.Vulnerability{{
				FixedIn: "1.2.5",
			}},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
		{
			name:           "current version requires comparable fixes",
			currentVersion: "1.2.5",
			vulnerabilities: []model.Vulnerability{{
				FixedVersions: []string{"release-a", "1.2.6"},
			}},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
		{
			name:           "unparseable installed version cannot prove an upgrade",
			currentVersion: "1:2.0",
			vulnerabilities: []model.Vulnerability{{
				FixedIn: "1.5.0",
			}},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
		{
			name:           "distribution installed version cannot prove an upgrade",
			currentVersion: "2:1.2.3-1ubuntu1",
			vulnerabilities: []model.Vulnerability{{
				FixedIn: "2.0.0",
			}},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
		{
			name: "unparseable fix evidence is not a version",
			vulnerabilities: []model.Vulnerability{{
				FixedIn: "see advisory",
			}},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
		{
			name:           "prerelease-only fix is not recommended",
			currentVersion: "1.0.0",
			vulnerabilities: []model.Vulnerability{{
				FixedIn: "2.0.0-rc.1",
			}},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
		{
			name:           "stable fix is preferred over prerelease",
			currentVersion: "1.0.0",
			vulnerabilities: []model.Vulnerability{{
				FixedVersions: []string{"2.0.0-rc.1", "2.0.0"},
			}},
			want: &model.PackageRemediation{
				Status:             model.PackageRemediationComplete,
				RecommendedVersion: "2.0.0",
			},
		},
		{
			name: "mixed fix and missing evidence",
			vulnerabilities: []model.Vulnerability{
				{ID: "VULN-1", FixedIn: "1.2.0"},
				{ID: "VULN-2"},
			},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
		{
			name: "mixed fix and unavailable",
			vulnerabilities: []model.Vulnerability{
				{ID: "VULN-1", FixedIn: "1.2.0"},
				{ID: "VULN-2", FixState: model.FixStateNotFixed},
			},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
		{
			name: "all unavailable",
			vulnerabilities: []model.Vulnerability{
				{ID: "VULN-1", FixState: model.FixStateNotFixed},
				{ID: "VULN-2", FixState: model.FixStateWontFix},
			},
			want: &model.PackageRemediation{Status: model.PackageRemediationUnavailable},
		},
		{
			name: "unknown evidence",
			vulnerabilities: []model.Vulnerability{
				{ID: "VULN-1"},
				{ID: "VULN-2", FixState: model.FixStateNotFixed},
			},
			want: &model.PackageRemediation{Status: model.PackageRemediationUnknown},
		},
		{
			name: "contradictory evidence",
			vulnerabilities: []model.Vulnerability{{
				FixState: model.FixStateWontFix,
				FixedIn:  "1.2.0",
			}},
			want: &model.PackageRemediation{Status: model.PackageRemediationUnknown},
		},
		{
			name: "incomparable versions across vulnerabilities",
			vulnerabilities: []model.Vulnerability{
				{ID: "VULN-1", FixedIn: "release-a"},
				{ID: "VULN-2", FixedIn: "release-b"},
			},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
		{
			name: "incomparable versions within one source",
			vulnerabilities: []model.Vulnerability{{
				FixedVersions: []string{"release-a", "release-b"},
			}},
			want: &model.PackageRemediation{Status: model.PackageRemediationPartial},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := derivePackageRemediation(tt.currentVersion, tt.vulnerabilities)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("derivePackageRemediation() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestDerivePackageRemediationsOverwritesAndIsIdempotent(t *testing.T) {
	registry := model.NewPackageRegistry()
	pkg := registry.Add(&model.Package{
		Coordinates: model.Coordinates{PURL: "pkg:npm/example@1.0.0"},
		Vulnerabilities: []model.Vulnerability{{
			FixedIn: "1.2.0",
		}},
		Remediation: &model.PackageRemediation{
			Status:             model.PackageRemediationComplete,
			RecommendedVersion: "99.0.0",
		},
	})

	derivePackageSummaries(registry)
	first := pkg.Remediation.Clone()
	derivePackageSummaries(registry)
	if !reflect.DeepEqual(pkg.Remediation, first) {
		t.Fatalf("second derivation changed result: first %#v, second %#v", first, pkg.Remediation)
	}
	if pkg.Remediation.RecommendedVersion != "1.2.0" {
		t.Fatalf("incoming remediation remained authoritative: %#v", pkg.Remediation)
	}
}

func TestDerivePackageRemediationIsOrderIndependent(t *testing.T) {
	first := []model.Vulnerability{
		{ID: "VULN-1", FixedIn: "1.2.0"},
		{ID: "VULN-2", FixedIn: "2.0.0"},
	}
	second := []model.Vulnerability{first[1], first[0]}

	if !reflect.DeepEqual(derivePackageRemediation("1.0.0", first), derivePackageRemediation("1.0.0", second)) {
		t.Fatalf("derivation changed with matcher order: %#v != %#v",
			derivePackageRemediation("1.0.0", first), derivePackageRemediation("1.0.0", second))
	}
}

type remediationTestDetector struct {
	descriptor plugin.DetectorDescriptor
	response   plugin.RemediationHintResponse
	err        error
}

func (d remediationTestDetector) Descriptor() plugin.DetectorDescriptor { return d.descriptor }
func (d remediationTestDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return nil
}
func (d remediationTestDetector) Ready(context.Context, plugin.DetectionRequest) error { return nil }
func (d remediationTestDetector) Applicable(context.Context, plugin.DetectionRequest) (bool, error) {
	return true, nil
}
func (d remediationTestDetector) ResolveGraph(context.Context, plugin.DetectionRequest) (plugin.DetectionResult, error) {
	return plugin.DetectionResult{}, nil
}
func (d remediationTestDetector) RemediationHints(
	_ context.Context,
	request plugin.RemediationHintRequest,
) (plugin.RemediationHintResponse, error) {
	if request.Registry != nil {
		request.Registry.Ensure("pkg:npm/mutated@1.0.0")
	}
	if request.Detection.Graphs != nil && len(request.Detection.Graphs.Entries) > 0 {
		request.Detection.Graphs.Entries[0].Manifest.Path = "mutated"
	}
	if len(request.Detection.SubprojectInfo.DetectedPackageManagers) > 0 {
		request.Detection.SubprojectInfo.DetectedPackageManagers[0] = model.PackageManagerGoMod
	}
	if len(request.Detection.SubprojectInfo.PlannedDetectors) > 0 {
		request.Detection.SubprojectInfo.PlannedDetectors[0] = "mutated"
	}
	return d.response, d.err
}

func TestDeriveBuildsCanonicalOccurrenceSuggestions(t *testing.T) {
	const manifestPath = "package-lock.json"
	graph := model.New()
	nodes := []*model.DependencyNode{
		testDependency("root", "", model.DependencyRelationshipDirect, model.DependencySourceProject),
		testDependency("direct", "pkg:npm/direct@1.0.0", model.DependencyRelationshipDirect, model.DependencySourceRegistry),
		testDependency("parent", "pkg:npm/parent@1.0.0", model.DependencyRelationshipDirect, model.DependencySourceRegistry),
		testDependency("transitive", "pkg:npm/transitive@1.0.0", model.DependencyRelationshipTransitive, model.DependencySourceRegistry),
		testDependency("refresh", "pkg:npm/refresh@1.0.0", model.DependencyRelationshipTransitive, model.DependencySourceRegistry),
		testDependency("unknown", "pkg:npm/unknown@1.0.0", model.DependencyRelationshipUnknown, model.DependencySourceRegistry),
		testDependency("workspace", "pkg:npm/workspace@1.0.0", model.DependencyRelationshipDirect, model.DependencySourceWorkspace),
		testDependency("unavailable", "pkg:npm/unavailable@1.0.0", model.DependencyRelationshipDirect, model.DependencySourceRegistry),
	}
	for _, node := range nodes {
		if err := graph.AddNode(node); err != nil {
			t.Fatalf("AddNode(%s) error = %v", node.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{
		{"root", "direct"},
		{"root", "parent"},
		{"parent", "transitive"},
		{"parent", "refresh"},
		{"root", "unknown"},
		{"root", "workspace"},
		{"root", "unavailable"},
	} {
		if err := graph.AddEdge(testnodes.ID(graph, edge[0]), testnodes.ID(graph, edge[1])); err != nil {
			t.Fatalf("AddEdge(%v) error = %v", edge, err)
		}
	}

	registry := model.NewPackageRegistry()
	for _, node := range nodes[1:] {
		vulnerability := model.Vulnerability{ID: "VULN-" + node.NodeID(), FixedIn: "1.2.0"}
		if testnodes.Is(node, "unavailable") {
			vulnerability = model.Vulnerability{ID: "VULN-unavailable", FixState: model.FixStateNotFixed}
		}
		registry.Add(&model.Package{
			Coordinates:     node.Coordinates,
			Vulnerabilities: []model.Vulnerability{vulnerability},
		})
	}

	detection := plugin.DetectionResult{
		DetectorName: "test-detector",
		SubprojectInfo: plugin.Subproject{
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			PlannedDetectors:        []string{"test-detector"},
		},
		Graphs: &model.GraphContainer{Entries: []model.GraphEntry{{
			Graph:    graph,
			Manifest: model.ManifestMetadata{Path: manifestPath},
		}}},
	}
	detector := remediationTestDetector{
		descriptor: plugin.DetectorDescriptor{
			Name: "test-detector",
			RemediationCapabilities: []plugin.RemediationCapability{{
				SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
				Actions: []model.RemediationAction{
					model.RemediationActionDirectBump,
					model.RemediationActionTransitiveOverride,
					model.RemediationActionLockfileRefresh,
				},
			}},
		},
		response: plugin.RemediationHintResponse{Hints: []plugin.RemediationHint{
			{
				DependencyRef: "pkg:npm/direct@1.0.0",
				ManifestPath:  manifestPath,
				Strategies: []plugin.RemediationStrategyHint{{
					Action: model.RemediationActionDirectBump,
				}},
			},
			{
				DependencyRef: "pkg:npm/transitive@1.0.0",
				ManifestPath:  manifestPath,
				Strategies: []plugin.RemediationStrategyHint{{
					Action: model.RemediationActionTransitiveOverride,
					Advice: `add "overrides": {"transitive": "1.2.0"}`,
				}},
			},
			{
				DependencyRef: "pkg:npm/refresh@1.0.0",
				ManifestPath:  manifestPath,
				Strategies: []plugin.RemediationStrategyHint{{
					Action: model.RemediationActionLockfileRefresh,
				}},
			},
			{
				DependencyRef: "pkg:npm/unknown@1.0.0",
				ManifestPath:  manifestPath,
				Strategies: []plugin.RemediationStrategyHint{{
					Action: model.RemediationActionDirectBump,
				}},
			},
			{
				DependencyRef: "pkg:npm/workspace@1.0.0",
				ManifestPath:  manifestPath,
				Strategies: []plugin.RemediationStrategyHint{{
					Action: model.RemediationActionDirectBump,
				}},
			},
		}},
	}

	warnings := Derive(context.Background(), Input{
		Registry: registry,
		Manifests: []plugin.ConsolidatedManifest{{
			Entry:        detection.Graphs.Entries[0],
			DetectorName: detection.DetectorName,
		}},
		Detections: []plugin.DetectionResult{detection},
		Detectors:  map[string]plugin.Detector{"test-detector": detector},
	})
	if len(warnings) != 0 {
		t.Fatalf("Derive() warnings = %#v", warnings)
	}
	if _, ok := registry.Get("pkg:npm/mutated@1.0.0"); ok {
		t.Fatal("detector mutated the authoritative registry")
	}
	if detection.Graphs.Entries[0].Manifest.Path != manifestPath {
		t.Fatalf("detector mutated detection input: %#v", detection.Graphs.Entries[0].Manifest)
	}
	if detection.SubprojectInfo.DetectedPackageManagers[0] != model.PackageManagerNPM ||
		detection.SubprojectInfo.PlannedDetectors[0] != "test-detector" {
		t.Fatalf("detector mutated subproject input: %#v", detection.SubprojectInfo)
	}

	// Targets are node IDs, and a node ID is a canonical package URL now.
	assertSuggestion(t, registry, "pkg:npm/direct@1.0.0", model.RemediationActionDirectBump, "pkg:npm/direct@1.0.0", "")
	assertSuggestion(t, registry, "pkg:npm/transitive@1.0.0", model.RemediationActionTransitiveOverride, "pkg:npm/parent@1.0.0", `add "overrides": {"transitive": "1.2.0"}`)
	assertSuggestion(t, registry, "pkg:npm/refresh@1.0.0", model.RemediationActionLockfileRefresh, "pkg:npm/parent@1.0.0", "")
	assertSuggestion(t, registry, "pkg:npm/unknown@1.0.0", model.RemediationActionManualReview, "pkg:npm/unknown@1.0.0", "")
	assertSuggestion(t, registry, "pkg:npm/workspace@1.0.0", model.RemediationActionManualReview, "pkg:npm/workspace@1.0.0", "")
	assertSuggestion(t, registry, "pkg:npm/unavailable@1.0.0", model.RemediationActionNoFixUpstream, "pkg:npm/unavailable@1.0.0", "")
}

// One package reached from two places in a manifest is one node -- the alias
// entry folds into it -- while the same package in another manifest keeps its
// own entry, so a suggestion is still made per manifest.
func TestDeriveFoldsWithinAManifestAndKeepsManifestsApart(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	firstGraph := model.New()
	for _, dependency := range []*model.DependencyNode{
		testDependency("root", "", model.DependencyRelationshipDirect, model.DependencySourceProject),
		testDependency("parent", "pkg:npm/parent@1.0.0", model.DependencyRelationshipDirect, model.DependencySourceRegistry),
		testDependency("example", purl, model.DependencyRelationshipTransitive, model.DependencySourceRegistry),
		testDependency("alias-example", purl, model.DependencyRelationshipTransitive, model.DependencySourceRegistry),
	} {
		// Inserted, not added: the alias shares the package URL, so it folds
		// into the node already there rather than failing as a duplicate.
		if _, err := firstGraph.InsertNode(dependency); err != nil {
			t.Fatalf("InsertNode(%s) error = %v", dependency.NodeID(), err)
		}
	}
	if err := firstGraph.AddEdge(testnodes.ID(firstGraph, "root"), testnodes.ID(firstGraph, "parent")); err != nil {
		t.Fatalf("AddEdge(parent) error = %v", err)
	}
	if err := firstGraph.AddEdge(testnodes.ID(firstGraph, "parent"), purl); err != nil {
		t.Fatalf("AddEdge(example) error = %v", err)
	}

	secondGraph := model.New()
	secondRoot := testDependency("workspace-root", "", model.DependencyRelationshipDirect, model.DependencySourceProject)
	secondParent := testDependency("workspace-parent", "pkg:npm/workspace-parent@1.0.0", model.DependencyRelationshipDirect, model.DependencySourceRegistry)
	secondOccurrence := testDependency("workspace-example", purl, model.DependencyRelationshipTransitive, model.DependencySourceRegistry)
	for _, dependency := range []*model.DependencyNode{secondRoot, secondParent, secondOccurrence} {
		if err := secondGraph.AddNode(dependency); err != nil {
			t.Fatalf("AddNode(%s) error = %v", dependency.NodeID(), err)
		}
	}
	if err := secondGraph.AddEdge(secondRoot.NodeID(), secondParent.NodeID()); err != nil {
		t.Fatalf("AddEdge() error = %v", err)
	}
	if err := secondGraph.AddEdge(secondParent.NodeID(), secondOccurrence.NodeID()); err != nil {
		t.Fatalf("AddEdge() error = %v", err)
	}

	entries := []model.GraphEntry{
		{Graph: firstGraph, Manifest: model.ManifestMetadata{Path: "package-lock.json"}},
		{Graph: secondGraph, Manifest: model.ManifestMetadata{Path: "packages/web/package-lock.json"}},
	}
	detection := plugin.DetectionResult{
		DetectorName: "test-detector",
		Graphs:       &model.GraphContainer{Entries: entries},
	}
	detector := remediationTestDetector{
		descriptor: plugin.DetectorDescriptor{
			Name: "test-detector",
			RemediationCapabilities: []plugin.RemediationCapability{{
				SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
				Actions:           []model.RemediationAction{model.RemediationActionTransitiveOverride},
			}},
		},
		response: plugin.RemediationHintResponse{Hints: []plugin.RemediationHint{
			// Both first-manifest hints name the one folded node, so the
			// second is a duplicate rather than a second occurrence.
			overrideHint(purl, entries[0].Manifest.Path),
			overrideHint(purl, entries[0].Manifest.Path),
			overrideHint(purl, entries[1].Manifest.Path),
		}},
	}
	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates: model.Coordinates{PURL: purl, Name: "example", Version: "1.0.0"},
		Vulnerabilities: []model.Vulnerability{{
			FixedIn: "1.2.0",
		}},
	})

	warnings := Derive(context.Background(), Input{
		Registry: registry,
		Manifests: []plugin.ConsolidatedManifest{
			{Entry: entries[0], DetectorName: detection.DetectorName},
			{Entry: entries[1], DetectorName: detection.DetectorName},
		},
		Detections: []plugin.DetectionResult{detection},
		Detectors:  map[string]plugin.Detector{"test-detector": detector},
	})
	if len(warnings) != 0 {
		t.Fatalf("Derive() warnings = %#v", warnings)
	}

	pkg, ok := registry.Get(purl)
	if !ok || pkg.Remediation == nil {
		t.Fatalf("package remediation missing: %#v", pkg)
	}
	if len(pkg.Remediation.Suggestions) != 2 {
		t.Fatalf("suggestions = %#v, want one group per manifest", pkg.Remediation.Suggestions)
	}
	if got := pkg.Remediation.Suggestions[0]; got.ManifestPath != "package-lock.json" ||
		!reflect.DeepEqual(got.AffectedDependencyRefs, []string{purl}) {
		t.Fatalf("root manifest suggestion = %#v", got)
	}
	if got := pkg.Remediation.Suggestions[1]; got.ManifestPath != "packages/web/package-lock.json" ||
		!reflect.DeepEqual(got.AffectedDependencyRefs, []string{purl}) {
		t.Fatalf("workspace manifest suggestion = %#v", got)
	}
}

func TestInferredPlacementUsesRealProjectRootsOnly(t *testing.T) {
	graph := model.New()
	root := testDependency("root", "", "", model.DependencySourceProject)
	direct := testDependency("direct", "pkg:npm/direct@1.0.0", "", model.DependencySourceRegistry)
	transitive := testDependency("transitive", "pkg:npm/transitive@1.0.0", "", model.DependencySourceRegistry)
	for _, dependency := range []*model.DependencyNode{root, direct, transitive} {
		if err := graph.AddNode(dependency); err != nil {
			t.Fatalf("AddNode(%s) error = %v", dependency.NodeID(), err)
		}
	}
	if err := graph.AddEdge(root.NodeID(), direct.NodeID()); err != nil {
		t.Fatalf("AddEdge(root, direct) error = %v", err)
	}
	if err := graph.AddEdge(direct.NodeID(), transitive.NodeID()); err != nil {
		t.Fatalf("AddEdge(direct, transitive) error = %v", err)
	}

	if relationship, target, ok := inferredPlacement(graph, direct.NodeID()); !ok ||
		relationship != model.DependencyRelationshipDirect || target != direct.NodeID() {
		t.Fatalf("direct placement = (%q, %q, %t)", relationship, target, ok)
	}
	if relationship, target, ok := inferredPlacement(graph, transitive.NodeID()); !ok ||
		relationship != model.DependencyRelationshipTransitive || target != direct.NodeID() {
		t.Fatalf("transitive placement = (%q, %q, %t)", relationship, target, ok)
	}

	virtualGraph := model.New()
	virtualRoot := testDependency("manifest", "", "", "")
	virtualRoot.Type = model.PackageTypeManifest
	orphan := testDependency("orphan", "pkg:npm/orphan@1.0.0", "", model.DependencySourceRegistry)
	for _, dependency := range []*model.DependencyNode{virtualRoot, orphan} {
		if err := virtualGraph.AddNode(dependency); err != nil {
			t.Fatalf("AddNode(%s) error = %v", dependency.NodeID(), err)
		}
	}
	if err := virtualGraph.AddEdge(virtualRoot.NodeID(), orphan.NodeID()); err != nil {
		t.Fatalf("AddEdge(manifest, orphan) error = %v", err)
	}
	if relationship, target, ok := inferredPlacement(virtualGraph, orphan.NodeID()); ok ||
		relationship != model.DependencyRelationshipUnknown || target != orphan.NodeID() {
		t.Fatalf("virtual-root placement = (%q, %q, %t)", relationship, target, ok)
	}
}

func TestInferredPlacementCollapsesEqualLengthDiamondPaths(t *testing.T) {
	graph := model.New()
	root := testDependency("root", "", "", model.DependencySourceProject)
	if err := graph.AddNode(root); err != nil {
		t.Fatal(err)
	}
	previous := []string{root.NodeID()}
	for layer := range 20 {
		current := []string{
			fmt.Sprintf("a-%02d", layer),
			fmt.Sprintf("b-%02d", layer),
		}
		nodeIDs := make([]string, 0, len(current))
		for _, id := range current {
			node := testDependency(id, "pkg:npm/"+id+"@1.0.0", "", model.DependencySourceRegistry)
			if err := graph.AddNode(node); err != nil {
				t.Fatal(err)
			}
			nodeIDs = append(nodeIDs, node.NodeID())
			for _, parent := range previous {
				if err := graph.AddEdge(parent, node.NodeID()); err != nil {
					t.Fatal(err)
				}
			}
		}
		previous = nodeIDs
	}
	target := testDependency("target", "pkg:npm/target@1.0.0", "", model.DependencySourceRegistry)
	if err := graph.AddNode(target); err != nil {
		t.Fatal(err)
	}
	for _, parent := range previous {
		if err := graph.AddEdge(parent, target.NodeID()); err != nil {
			t.Fatal(err)
		}
	}

	relationship, directTarget, ok := inferredPlacement(graph, target.NodeID())
	if !ok || relationship != model.DependencyRelationshipTransitive || directTarget != "pkg:npm/a-00@1.0.0" {
		t.Fatalf("diamond placement = (%q, %q, %t)", relationship, directTarget, ok)
	}
}

func TestValidateHintsSanitizesAndBoundsAdvice(t *testing.T) {
	graph := model.New()
	dependency := testDependency(
		"dependency",
		"pkg:npm/dependency@1.0.0",
		model.DependencyRelationshipTransitive,
		model.DependencySourceRegistry,
	)
	if err := graph.AddNode(dependency); err != nil {
		t.Fatal(err)
	}
	detection := plugin.DetectionResult{
		DetectorName: "test-detector",
		Graphs: model.SingleGraphContainer(
			graph,
			model.ManifestMetadata{Path: "package-lock.json"},
		),
	}
	descriptor := plugin.DetectorDescriptor{
		Name:              "test-detector",
		SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
		RemediationCapabilities: []plugin.RemediationCapability{{
			SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
			Actions:           []model.RemediationAction{model.RemediationActionTransitiveOverride},
		}},
	}
	rawAdvice := "\x1b[31m" + strings.Repeat("x", maxDetectorAdviceRunes+100) + "\nspoofed"
	validated, rejected := validateHints(detection, descriptor, []plugin.RemediationHint{{
		DependencyRef: dependency.NodeID(),
		ManifestPath:  "package-lock.json",
		Strategies: []plugin.RemediationStrategyHint{{
			Action: model.RemediationActionTransitiveOverride,
			Advice: rawAdvice,
		}},
	}})
	if len(rejected) != 0 || len(validated) != 1 {
		t.Fatalf("validateHints() = %#v, %#v", validated, rejected)
	}
	advice := validated[0].strategies[model.RemediationActionTransitiveOverride]
	if utf8.RuneCountInString(advice) > maxDetectorAdviceRunes {
		t.Fatalf("advice has %d runes", utf8.RuneCountInString(advice))
	}
	for _, r := range advice {
		if unicode.IsControl(r) {
			t.Fatalf("advice contains control character %U: %q", r, advice)
		}
	}
}

func TestCollectHintsBoundsAndSanitizesDiagnostics(t *testing.T) {
	diagnostics := make([]string, maxDetectorDiagnostics+5)
	for idx := range diagnostics {
		diagnostics[idx] = fmt.Sprintf("\x1b[31mdiagnostic-%02d %s", idx,
			strings.Repeat("x", maxDetectorDiagnosticRunes))
	}
	detection := plugin.DetectionResult{DetectorName: "test-detector"}
	detector := remediationTestDetector{
		descriptor: plugin.DetectorDescriptor{
			Name: "test-detector",
			RemediationCapabilities: []plugin.RemediationCapability{{
				SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
				Actions:           []model.RemediationAction{model.RemediationActionDirectBump},
			}},
		},
		response: plugin.RemediationHintResponse{Diagnostics: diagnostics},
	}
	_, warnings := collectHints(context.Background(), Input{
		Registry:   model.NewPackageRegistry(),
		Detections: []plugin.DetectionResult{detection, detection},
		Detectors:  map[string]plugin.Detector{"test-detector": detector},
	})
	if len(warnings) != maxDetectorDiagnostics+1 {
		t.Fatalf("warnings = %d, want %d: %#v",
			len(warnings), maxDetectorDiagnostics+1, warnings)
	}
	for _, warning := range warnings {
		if utf8.RuneCountInString(warning.Message) > maxDetectorDiagnosticRunes {
			t.Fatalf("warning has %d runes: %q", utf8.RuneCountInString(warning.Message), warning.Message)
		}
		for _, r := range warning.Message {
			if unicode.IsControl(r) {
				t.Fatalf("warning contains control character %U: %q", r, warning.Message)
			}
		}
	}
	if !strings.Contains(warnings[len(warnings)-1].Message, "30 additional") {
		t.Fatalf("omission summary = %q, want 30 additional warnings",
			warnings[len(warnings)-1].Message)
	}
}

func overrideHint(dependencyRef, manifestPath string) plugin.RemediationHint {
	return plugin.RemediationHint{
		DependencyRef: dependencyRef,
		ManifestPath:  manifestPath,
		Strategies: []plugin.RemediationStrategyHint{{
			Action: model.RemediationActionTransitiveOverride,
			Advice: "use the package manager override field",
		}},
	}
}

func TestDeriveRejectsUnadvertisedAndUnknownHints(t *testing.T) {
	graph := model.New()
	dependency := testDependency("direct", "pkg:npm/direct@1.0.0", model.DependencyRelationshipDirect, model.DependencySourceRegistry)
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates: dependency.Coordinates,
		Vulnerabilities: []model.Vulnerability{{
			FixedIn: "1.2.0",
		}},
	})
	detection := plugin.DetectionResult{
		DetectorName: "test-detector",
		Graphs: &model.GraphContainer{Entries: []model.GraphEntry{{
			Graph:    graph,
			Manifest: model.ManifestMetadata{Path: "package-lock.json"},
		}}},
	}
	detector := remediationTestDetector{
		descriptor: plugin.DetectorDescriptor{
			Name: "test-detector",
			RemediationCapabilities: []plugin.RemediationCapability{{
				SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
				Actions:           []model.RemediationAction{model.RemediationActionDirectBump},
			}},
		},
		response: plugin.RemediationHintResponse{Hints: []plugin.RemediationHint{
			{
				DependencyRef: "missing",
				ManifestPath:  "package-lock.json",
				Strategies: []plugin.RemediationStrategyHint{{
					Action: model.RemediationActionDirectBump,
				}},
			},
			{
				DependencyRef: "pkg:npm/direct@1.0.0",
				ManifestPath:  "package-lock.json",
				Strategies: []plugin.RemediationStrategyHint{{
					Action: model.RemediationActionTransitiveOverride,
				}},
			},
		}},
	}
	warnings := Derive(context.Background(), Input{
		Registry: registry,
		Manifests: []plugin.ConsolidatedManifest{{
			Entry:        detection.Graphs.Entries[0],
			DetectorName: detection.DetectorName,
		}},
		Detections: []plugin.DetectionResult{detection},
		Detectors:  map[string]plugin.Detector{"test-detector": detector},
	})
	if len(warnings) != 2 {
		t.Fatalf("Derive() warnings = %#v, want 2", warnings)
	}
	assertSuggestion(t, registry, dependency.PackageRef, model.RemediationActionManualReview, dependency.NodeID(), "")
}

func TestDeriveResolvesRebasedHintAndWarnsWhenManifestResolutionFails(t *testing.T) {
	const (
		purl         = "pkg:npm/example@1.0.0"
		manifestPath = "package-lock.json"
	)
	detectionGraph := model.New()
	rawDependency := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{
			PURL: purl, Name: "example", Version: "1.0.0",
			PackageManager: model.PackageManagerNPM,
		},
		Relationship: model.DependencyRelationshipDirect,
		Source:       model.DependencySourceRegistry,
	})
	if err := detectionGraph.AddNode(rawDependency); err != nil {
		t.Fatal(err)
	}
	detection := plugin.DetectionResult{
		DetectorName: "test-detector",
		Graphs: model.SingleGraphContainer(
			detectionGraph,
			model.ManifestMetadata{Path: manifestPath},
		),
	}
	detector := remediationTestDetector{
		descriptor: plugin.DetectorDescriptor{
			Name:              "test-detector",
			SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
			RemediationCapabilities: []plugin.RemediationCapability{{
				SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
				Actions:           []model.RemediationAction{model.RemediationActionDirectBump},
			}},
		},
		response: plugin.RemediationHintResponse{Hints: []plugin.RemediationHint{{
			DependencyRef: rawDependency.NodeID(),
			ManifestPath:  manifestPath,
			Strategies: []plugin.RemediationStrategyHint{{
				Action: model.RemediationActionDirectBump,
			}},
		}}},
	}

	newRegistry := func() *model.PackageRegistry {
		registry := model.NewPackageRegistry()
		registry.Add(&model.Package{
			Coordinates: model.Coordinates{
				PURL: purl, Name: "example", Version: "1.0.0",
			},
			Vulnerabilities: []model.Vulnerability{{ID: "VULN-1", FixedIn: "1.2.0"}},
		})
		return registry
	}

	t.Run("rebased dependency id", func(t *testing.T) {
		consolidated := model.New()
		rebased := testDependency(
			purl,
			purl,
			model.DependencyRelationshipDirect,
			model.DependencySourceRegistry,
		)
		if err := consolidated.AddNode(rebased); err != nil {
			t.Fatal(err)
		}
		registry := newRegistry()
		warnings := Derive(context.Background(), Input{
			Registry: registry,
			Manifests: []plugin.ConsolidatedManifest{{
				DetectorName: detection.DetectorName,
				Entry: model.GraphEntry{
					Graph: consolidated, Manifest: model.ManifestMetadata{Path: manifestPath},
				},
			}},
			Detections: []plugin.DetectionResult{detection},
			Detectors:  map[string]plugin.Detector{"test-detector": detector},
		})
		if len(warnings) != 0 {
			t.Fatalf("Derive() warnings = %#v", warnings)
		}
		assertSuggestion(t, registry, purl, model.RemediationActionDirectBump, purl, "")
	})

	t.Run("unresolved consolidated manifest", func(t *testing.T) {
		registry := newRegistry()
		warnings := Derive(context.Background(), Input{
			Registry: registry,
			Manifests: []plugin.ConsolidatedManifest{{
				DetectorName: detection.DetectorName,
				Entry: model.GraphEntry{
					Graph: model.New(), Manifest: model.ManifestMetadata{Path: manifestPath},
				},
			}},
			Detections: []plugin.DetectionResult{detection},
			Detectors:  map[string]plugin.Detector{"test-detector": detector},
		})
		if len(warnings) != 1 ||
			!strings.Contains(warnings[0].Message, "consolidated manifest could not be resolved") {
			t.Fatalf("Derive() warnings = %#v", warnings)
		}
		pkg, _ := registry.Get(purl)
		if pkg.Remediation == nil || len(pkg.Remediation.Suggestions) != 0 {
			t.Fatalf("unresolved hint produced suggestions: %#v", pkg.Remediation)
		}
	})
}

func TestDeriveFallsBackToManualReviewWhenProviderFails(t *testing.T) {
	graph := model.New()
	dependency := testDependency("direct", "pkg:npm/direct@1.0.0", model.DependencyRelationshipDirect, model.DependencySourceRegistry)
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates: dependency.Coordinates,
		Vulnerabilities: []model.Vulnerability{{
			FixedIn: "1.2.0",
		}},
	})
	detection := plugin.DetectionResult{
		DetectorName: "test-detector",
		Graphs: &model.GraphContainer{Entries: []model.GraphEntry{{
			Graph:    graph,
			Manifest: model.ManifestMetadata{Path: "package-lock.json"},
		}}},
	}
	detector := remediationTestDetector{
		descriptor: plugin.DetectorDescriptor{
			Name: "test-detector",
			RemediationCapabilities: []plugin.RemediationCapability{{
				SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
				Actions:           []model.RemediationAction{model.RemediationActionDirectBump},
			}},
		},
		err: errors.New("provider failed"),
	}
	warnings := Derive(context.Background(), Input{
		Registry: registry,
		Manifests: []plugin.ConsolidatedManifest{{
			Entry:        detection.Graphs.Entries[0],
			DetectorName: detection.DetectorName,
		}},
		Detections: []plugin.DetectionResult{detection},
		Detectors:  map[string]plugin.Detector{"test-detector": detector},
	})
	if len(warnings) != 1 || warnings[0].Message != "provider failed" {
		t.Fatalf("Derive() warnings = %#v", warnings)
	}
	assertSuggestion(t, registry, dependency.PackageRef, model.RemediationActionManualReview, dependency.NodeID(), "")
}

func testDependency(id, purl string, relationship model.DependencyRelationship, source model.DependencySource) *model.DependencyNode {
	return testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{
			PURL:           purl,
			Name:           id,
			Version:        "1.0.0",
			PackageManager: model.PackageManagerNPM,
			Type:           model.PackageTypePackage,
		},
		Relationship: relationship,
		Source:       source,
		PackageRef:   purl,
	})
}

func assertSuggestion(
	t *testing.T,
	registry *model.PackageRegistry,
	purl string,
	action model.RemediationAction,
	targetRef string,
	advice string,
) {
	t.Helper()
	pkg, ok := registry.Get(purl)
	if !ok || pkg == nil || pkg.Remediation == nil {
		t.Fatalf("package %q remediation missing: %#v", purl, pkg)
	}
	if len(pkg.Remediation.Suggestions) != 1 {
		t.Fatalf("package %q suggestions = %#v", purl, pkg.Remediation.Suggestions)
	}
	suggestion := pkg.Remediation.Suggestions[0]
	if suggestion.Action != action || suggestion.SuggestedActionDependencyRef != targetRef ||
		suggestion.OverrideAdvice != advice {
		t.Fatalf("package %q suggestion = %#v, want action %q target %q advice %q", purl, suggestion, action, targetRef, advice)
	}
}
