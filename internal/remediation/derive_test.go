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

	"github.com/bomly-dev/bomly-sdk"
)

func TestDerivePackageRemediation(t *testing.T) {
	tests := []struct {
		name            string
		currentVersion  string
		vulnerabilities []sdk.Vulnerability
		want            *sdk.PackageRemediation
	}{
		{
			name: "no vulnerabilities",
		},
		{
			name: "one fixed in version",
			vulnerabilities: []sdk.Vulnerability{{
				ID:       "VULN-1",
				FixState: sdk.FixStateFixed,
				FixedIn:  "1.2.0",
			}},
			want: &sdk.PackageRemediation{
				Status:             sdk.PackageRemediationComplete,
				RecommendedVersion: "1.2.0",
			},
		},
		{
			name: "uses preferred source and highest required version",
			vulnerabilities: []sdk.Vulnerability{
				{
					ID:            "VULN-1",
					FixedIn:       "1.4.0",
					FixAvailable:  []sdk.FixAvailable{{Version: "9.0.0"}},
					FixedVersions: []string{"8.0.0"},
				},
				{
					ID: "VULN-2",
					FixAvailable: []sdk.FixAvailable{
						{Version: "2.1.0"},
						{Version: "2.0.0"},
					},
					FixedVersions: []string{"7.0.0"},
				},
				{
					ID:            "VULN-3",
					FixedVersions: []string{"1.5.0", "1.6.0"},
				},
			},
			want: &sdk.PackageRemediation{
				Status:             sdk.PackageRemediationComplete,
				RecommendedVersion: "2.0.0",
			},
		},
		{
			name:           "selects fix from current release line",
			currentVersion: "1.2.5",
			vulnerabilities: []sdk.Vulnerability{{
				ID:            "VULN-1",
				FixedVersions: []string{"0.2.4", "1.2.6"},
			}},
			want: &sdk.PackageRemediation{
				Status:             sdk.PackageRemediationComplete,
				RecommendedVersion: "1.2.6",
			},
		},
		{
			name:           "does not recommend a downgrade",
			currentVersion: "1.2.5",
			vulnerabilities: []sdk.Vulnerability{{
				ID:            "VULN-1",
				FixedVersions: []string{"0.2.4", "1.2.4"},
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name:           "does not recommend installed version",
			currentVersion: "1.2.5",
			vulnerabilities: []sdk.Vulnerability{{
				ID:      "VULN-1",
				FixedIn: "1.2.5",
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name:           "current version requires comparable fixes",
			currentVersion: "1.2.5",
			vulnerabilities: []sdk.Vulnerability{{
				ID:            "VULN-1",
				FixedVersions: []string{"release-a", "1.2.6"},
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name:           "unparseable installed version cannot prove an upgrade",
			currentVersion: "1:2.0",
			vulnerabilities: []sdk.Vulnerability{{
				ID:      "VULN-1",
				FixedIn: "1.5.0",
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name:           "distribution installed version cannot prove an upgrade",
			currentVersion: "2:1.2.3-1ubuntu1",
			vulnerabilities: []sdk.Vulnerability{{
				ID:      "VULN-1",
				FixedIn: "2.0.0",
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name: "unparseable fix evidence is not a version",
			vulnerabilities: []sdk.Vulnerability{{
				ID:      "VULN-1",
				FixedIn: "see advisory",
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name:           "prerelease-only fix is not recommended",
			currentVersion: "1.0.0",
			vulnerabilities: []sdk.Vulnerability{{
				ID:      "VULN-1",
				FixedIn: "2.0.0-rc.1",
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name:           "stable fix is preferred over prerelease",
			currentVersion: "1.0.0",
			vulnerabilities: []sdk.Vulnerability{{
				ID:            "VULN-1",
				FixedVersions: []string{"2.0.0-rc.1", "2.0.0"},
			}},
			want: &sdk.PackageRemediation{
				Status:             sdk.PackageRemediationComplete,
				RecommendedVersion: "2.0.0",
			},
		},
		{
			name: "mixed fix and missing evidence",
			vulnerabilities: []sdk.Vulnerability{
				{ID: "VULN-1", FixedIn: "1.2.0"},
				{ID: "VULN-2"},
			},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name: "mixed fix and unavailable",
			vulnerabilities: []sdk.Vulnerability{
				{ID: "VULN-1", FixedIn: "1.2.0"},
				{ID: "VULN-2", FixState: sdk.FixStateNotFixed},
			},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name: "all unavailable",
			vulnerabilities: []sdk.Vulnerability{
				{ID: "VULN-1", FixState: sdk.FixStateNotFixed},
				{ID: "VULN-2", FixState: sdk.FixStateWontFix},
			},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationUnavailable},
		},
		{
			name: "unknown evidence",
			vulnerabilities: []sdk.Vulnerability{
				{ID: "VULN-1"},
				{ID: "VULN-2", FixState: sdk.FixStateNotFixed},
			},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationUnknown},
		},
		{
			name: "contradictory evidence",
			vulnerabilities: []sdk.Vulnerability{{
				ID:       "VULN-1",
				FixState: sdk.FixStateWontFix,
				FixedIn:  "1.2.0",
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationUnknown},
		},
		{
			name: "incomparable versions across vulnerabilities",
			vulnerabilities: []sdk.Vulnerability{
				{ID: "VULN-1", FixedIn: "release-a"},
				{ID: "VULN-2", FixedIn: "release-b"},
			},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name: "incomparable versions within one source",
			vulnerabilities: []sdk.Vulnerability{{
				ID:            "VULN-1",
				FixedVersions: []string{"release-a", "release-b"},
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
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
	registry := sdk.NewPackageRegistry()
	pkg := registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: "pkg:npm/example@1.0.0"},
		Vulnerabilities: []sdk.Vulnerability{{
			ID:      "VULN-1",
			FixedIn: "1.2.0",
		}},
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
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
	first := []sdk.Vulnerability{
		{ID: "VULN-1", FixedIn: "1.2.0"},
		{ID: "VULN-2", FixedIn: "2.0.0"},
	}
	second := []sdk.Vulnerability{first[1], first[0]}

	if !reflect.DeepEqual(derivePackageRemediation("1.0.0", first), derivePackageRemediation("1.0.0", second)) {
		t.Fatalf("derivation changed with matcher order: %#v != %#v",
			derivePackageRemediation("1.0.0", first), derivePackageRemediation("1.0.0", second))
	}
}

type remediationTestDetector struct {
	descriptor sdk.DetectorDescriptor
	response   sdk.RemediationHintResponse
	err        error
}

func (d remediationTestDetector) Descriptor() sdk.DetectorDescriptor { return d.descriptor }
func (d remediationTestDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return nil
}
func (d remediationTestDetector) Ready(context.Context, sdk.DetectionRequest) error { return nil }
func (d remediationTestDetector) Applicable(context.Context, sdk.DetectionRequest) (bool, error) {
	return true, nil
}
func (d remediationTestDetector) ResolveGraph(context.Context, sdk.DetectionRequest) (sdk.DetectionResult, error) {
	return sdk.DetectionResult{}, nil
}
func (d remediationTestDetector) RemediationHints(
	_ context.Context,
	request sdk.RemediationHintRequest,
) (sdk.RemediationHintResponse, error) {
	if request.Registry != nil {
		request.Registry.Ensure("pkg:npm/mutated@1.0.0")
	}
	if request.Detection.Graphs != nil && len(request.Detection.Graphs.Entries) > 0 {
		request.Detection.Graphs.Entries[0].Manifest.Path = "mutated"
	}
	if len(request.Detection.SubprojectInfo.DetectedPackageManagers) > 0 {
		request.Detection.SubprojectInfo.DetectedPackageManagers[0] = sdk.PackageManagerGoMod
	}
	if len(request.Detection.SubprojectInfo.PlannedDetectors) > 0 {
		request.Detection.SubprojectInfo.PlannedDetectors[0] = "mutated"
	}
	return d.response, d.err
}

func TestDeriveBuildsCanonicalOccurrenceSuggestions(t *testing.T) {
	const manifestPath = "package-lock.json"
	graph := sdk.New()
	nodes := []*sdk.Dependency{
		testDependency("root", "", sdk.DependencyRelationshipDirect, sdk.DependencySourceProject),
		testDependency("direct", "pkg:npm/direct@1.0.0", sdk.DependencyRelationshipDirect, sdk.DependencySourceRegistry),
		testDependency("parent", "pkg:npm/parent@1.0.0", sdk.DependencyRelationshipDirect, sdk.DependencySourceRegistry),
		testDependency("transitive", "pkg:npm/transitive@1.0.0", sdk.DependencyRelationshipTransitive, sdk.DependencySourceRegistry),
		testDependency("refresh", "pkg:npm/refresh@1.0.0", sdk.DependencyRelationshipTransitive, sdk.DependencySourceRegistry),
		testDependency("unknown", "pkg:npm/unknown@1.0.0", sdk.DependencyRelationshipUnknown, sdk.DependencySourceRegistry),
		testDependency("workspace", "pkg:npm/workspace@1.0.0", sdk.DependencyRelationshipDirect, sdk.DependencySourceWorkspace),
		testDependency("unavailable", "pkg:npm/unavailable@1.0.0", sdk.DependencyRelationshipDirect, sdk.DependencySourceRegistry),
	}
	for _, node := range nodes {
		if err := graph.AddNode(node); err != nil {
			t.Fatalf("AddNode(%s) error = %v", node.ID, err)
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
		if err := graph.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("AddEdge(%v) error = %v", edge, err)
		}
	}

	registry := sdk.NewPackageRegistry()
	for _, node := range nodes[1:] {
		vulnerability := sdk.Vulnerability{ID: "VULN-" + node.ID, FixedIn: "1.2.0"}
		if node.ID == "unavailable" {
			vulnerability = sdk.Vulnerability{ID: "VULN-unavailable", FixState: sdk.FixStateNotFixed}
		}
		registry.Add(&sdk.Package{
			Coordinates:     node.Coordinates,
			Vulnerabilities: []sdk.Vulnerability{vulnerability},
		})
	}

	detection := sdk.DetectionResult{
		DetectorName: "test-detector",
		SubprojectInfo: sdk.Subproject{
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			PlannedDetectors:        []string{"test-detector"},
		},
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    graph,
			Manifest: sdk.ManifestMetadata{Path: manifestPath},
		}}},
	}
	detector := remediationTestDetector{
		descriptor: sdk.DetectorDescriptor{
			Name: "test-detector",
			RemediationCapabilities: []sdk.RemediationCapability{{
				SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Actions: []sdk.RemediationAction{
					sdk.RemediationActionDirectBump,
					sdk.RemediationActionTransitiveOverride,
					sdk.RemediationActionLockfileRefresh,
				},
			}},
		},
		response: sdk.RemediationHintResponse{Hints: []sdk.RemediationHint{
			{
				DependencyRef: "direct",
				ManifestPath:  manifestPath,
				Strategies: []sdk.RemediationStrategyHint{{
					Action: sdk.RemediationActionDirectBump,
				}},
			},
			{
				DependencyRef: "transitive",
				ManifestPath:  manifestPath,
				Strategies: []sdk.RemediationStrategyHint{{
					Action: sdk.RemediationActionTransitiveOverride,
					Advice: `add "overrides": {"transitive": "1.2.0"}`,
				}},
			},
			{
				DependencyRef: "refresh",
				ManifestPath:  manifestPath,
				Strategies: []sdk.RemediationStrategyHint{{
					Action: sdk.RemediationActionLockfileRefresh,
				}},
			},
			{
				DependencyRef: "unknown",
				ManifestPath:  manifestPath,
				Strategies: []sdk.RemediationStrategyHint{{
					Action: sdk.RemediationActionDirectBump,
				}},
			},
			{
				DependencyRef: "workspace",
				ManifestPath:  manifestPath,
				Strategies: []sdk.RemediationStrategyHint{{
					Action: sdk.RemediationActionDirectBump,
				}},
			},
		}},
	}

	warnings := Derive(context.Background(), Input{
		Registry: registry,
		Manifests: []sdk.ConsolidatedManifest{{
			Entry:        detection.Graphs.Entries[0],
			DetectorName: detection.DetectorName,
		}},
		Detections: []sdk.DetectionResult{detection},
		Detectors:  map[string]sdk.Detector{"test-detector": detector},
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
	if detection.SubprojectInfo.DetectedPackageManagers[0] != sdk.PackageManagerNPM ||
		detection.SubprojectInfo.PlannedDetectors[0] != "test-detector" {
		t.Fatalf("detector mutated subproject input: %#v", detection.SubprojectInfo)
	}

	assertSuggestion(t, registry, "pkg:npm/direct@1.0.0", sdk.RemediationActionDirectBump, "direct", "")
	assertSuggestion(t, registry, "pkg:npm/transitive@1.0.0", sdk.RemediationActionTransitiveOverride, "parent", `add "overrides": {"transitive": "1.2.0"}`)
	assertSuggestion(t, registry, "pkg:npm/refresh@1.0.0", sdk.RemediationActionLockfileRefresh, "parent", "")
	assertSuggestion(t, registry, "pkg:npm/unknown@1.0.0", sdk.RemediationActionManualReview, "unknown", "")
	assertSuggestion(t, registry, "pkg:npm/workspace@1.0.0", sdk.RemediationActionManualReview, "workspace", "")
	assertSuggestion(t, registry, "pkg:npm/unavailable@1.0.0", sdk.RemediationActionNoFixUpstream, "unavailable", "")
}

func TestDeriveGroupsEquivalentOccurrencesWithoutCollapsingManifests(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	firstGraph := sdk.New()
	for _, dependency := range []*sdk.Dependency{
		testDependency("root", "", sdk.DependencyRelationshipDirect, sdk.DependencySourceProject),
		testDependency("parent", "pkg:npm/parent@1.0.0", sdk.DependencyRelationshipDirect, sdk.DependencySourceRegistry),
		testDependency("example", purl, sdk.DependencyRelationshipTransitive, sdk.DependencySourceRegistry),
		testDependency("alias-example", purl, sdk.DependencyRelationshipTransitive, sdk.DependencySourceRegistry),
	} {
		if err := firstGraph.AddNode(dependency); err != nil {
			t.Fatalf("AddNode(%s) error = %v", dependency.ID, err)
		}
	}
	if err := firstGraph.AddEdge("root", "parent"); err != nil {
		t.Fatalf("AddEdge(parent) error = %v", err)
	}
	for _, dependencyRef := range []string{"example", "alias-example"} {
		if err := firstGraph.AddEdge("parent", dependencyRef); err != nil {
			t.Fatalf("AddEdge(%q) error = %v", dependencyRef, err)
		}
	}

	secondGraph := sdk.New()
	secondRoot := testDependency("workspace-root", "", sdk.DependencyRelationshipDirect, sdk.DependencySourceProject)
	secondParent := testDependency("workspace-parent", "pkg:npm/workspace-parent@1.0.0", sdk.DependencyRelationshipDirect, sdk.DependencySourceRegistry)
	secondOccurrence := testDependency("workspace-example", purl, sdk.DependencyRelationshipTransitive, sdk.DependencySourceRegistry)
	for _, dependency := range []*sdk.Dependency{secondRoot, secondParent, secondOccurrence} {
		if err := secondGraph.AddNode(dependency); err != nil {
			t.Fatalf("AddNode(%s) error = %v", dependency.ID, err)
		}
	}
	if err := secondGraph.AddEdge(secondRoot.ID, secondParent.ID); err != nil {
		t.Fatalf("AddEdge() error = %v", err)
	}
	if err := secondGraph.AddEdge(secondParent.ID, secondOccurrence.ID); err != nil {
		t.Fatalf("AddEdge() error = %v", err)
	}

	entries := []sdk.GraphEntry{
		{Graph: firstGraph, Manifest: sdk.ManifestMetadata{Path: "package-lock.json"}},
		{Graph: secondGraph, Manifest: sdk.ManifestMetadata{Path: "packages/web/package-lock.json"}},
	}
	detection := sdk.DetectionResult{
		DetectorName: "test-detector",
		Graphs:       &sdk.GraphContainer{Entries: entries},
	}
	detector := remediationTestDetector{
		descriptor: sdk.DetectorDescriptor{
			Name: "test-detector",
			RemediationCapabilities: []sdk.RemediationCapability{{
				SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Actions:           []sdk.RemediationAction{sdk.RemediationActionTransitiveOverride},
			}},
		},
		response: sdk.RemediationHintResponse{Hints: []sdk.RemediationHint{
			overrideHint("example", entries[0].Manifest.Path),
			overrideHint("alias-example", entries[0].Manifest.Path),
			overrideHint("workspace-example", entries[1].Manifest.Path),
		}},
	}
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: purl, Name: "example", Version: "1.0.0"},
		Vulnerabilities: []sdk.Vulnerability{{
			ID:      "VULN-1",
			FixedIn: "1.2.0",
		}},
	})

	warnings := Derive(context.Background(), Input{
		Registry: registry,
		Manifests: []sdk.ConsolidatedManifest{
			{Entry: entries[0], DetectorName: detection.DetectorName},
			{Entry: entries[1], DetectorName: detection.DetectorName},
		},
		Detections: []sdk.DetectionResult{detection},
		Detectors:  map[string]sdk.Detector{"test-detector": detector},
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
		!reflect.DeepEqual(got.AffectedDependencyRefs, []string{"alias-example", "example"}) {
		t.Fatalf("root manifest suggestion = %#v", got)
	}
	if got := pkg.Remediation.Suggestions[1]; got.ManifestPath != "packages/web/package-lock.json" ||
		!reflect.DeepEqual(got.AffectedDependencyRefs, []string{"workspace-example"}) {
		t.Fatalf("workspace manifest suggestion = %#v", got)
	}
}

func TestInferredPlacementUsesRealProjectRootsOnly(t *testing.T) {
	graph := sdk.New()
	root := testDependency("root", "", "", sdk.DependencySourceProject)
	direct := testDependency("direct", "pkg:npm/direct@1.0.0", "", sdk.DependencySourceRegistry)
	transitive := testDependency("transitive", "pkg:npm/transitive@1.0.0", "", sdk.DependencySourceRegistry)
	for _, dependency := range []*sdk.Dependency{root, direct, transitive} {
		if err := graph.AddNode(dependency); err != nil {
			t.Fatalf("AddNode(%s) error = %v", dependency.ID, err)
		}
	}
	if err := graph.AddEdge(root.ID, direct.ID); err != nil {
		t.Fatalf("AddEdge(root, direct) error = %v", err)
	}
	if err := graph.AddEdge(direct.ID, transitive.ID); err != nil {
		t.Fatalf("AddEdge(direct, transitive) error = %v", err)
	}

	if relationship, target, ok := inferredPlacement(graph, direct.ID); !ok ||
		relationship != sdk.DependencyRelationshipDirect || target != direct.ID {
		t.Fatalf("direct placement = (%q, %q, %t)", relationship, target, ok)
	}
	if relationship, target, ok := inferredPlacement(graph, transitive.ID); !ok ||
		relationship != sdk.DependencyRelationshipTransitive || target != direct.ID {
		t.Fatalf("transitive placement = (%q, %q, %t)", relationship, target, ok)
	}

	virtualGraph := sdk.New()
	virtualRoot := testDependency("manifest", "", "", "")
	virtualRoot.Type = sdk.PackageTypeManifest
	orphan := testDependency("orphan", "pkg:npm/orphan@1.0.0", "", sdk.DependencySourceRegistry)
	for _, dependency := range []*sdk.Dependency{virtualRoot, orphan} {
		if err := virtualGraph.AddNode(dependency); err != nil {
			t.Fatalf("AddNode(%s) error = %v", dependency.ID, err)
		}
	}
	if err := virtualGraph.AddEdge(virtualRoot.ID, orphan.ID); err != nil {
		t.Fatalf("AddEdge(manifest, orphan) error = %v", err)
	}
	if relationship, target, ok := inferredPlacement(virtualGraph, orphan.ID); ok ||
		relationship != sdk.DependencyRelationshipUnknown || target != orphan.ID {
		t.Fatalf("virtual-root placement = (%q, %q, %t)", relationship, target, ok)
	}
}

func TestInferredPlacementCollapsesEqualLengthDiamondPaths(t *testing.T) {
	graph := sdk.New()
	root := testDependency("root", "", "", sdk.DependencySourceProject)
	if err := graph.AddNode(root); err != nil {
		t.Fatal(err)
	}
	previous := []string{root.ID}
	for layer := 0; layer < 20; layer++ {
		current := []string{
			fmt.Sprintf("a-%02d", layer),
			fmt.Sprintf("b-%02d", layer),
		}
		for _, id := range current {
			node := testDependency(id, "pkg:npm/"+id+"@1.0.0", "", sdk.DependencySourceRegistry)
			if err := graph.AddNode(node); err != nil {
				t.Fatal(err)
			}
			for _, parent := range previous {
				if err := graph.AddEdge(parent, id); err != nil {
					t.Fatal(err)
				}
			}
		}
		previous = current
	}
	target := testDependency("target", "pkg:npm/target@1.0.0", "", sdk.DependencySourceRegistry)
	if err := graph.AddNode(target); err != nil {
		t.Fatal(err)
	}
	for _, parent := range previous {
		if err := graph.AddEdge(parent, target.ID); err != nil {
			t.Fatal(err)
		}
	}

	relationship, directTarget, ok := inferredPlacement(graph, target.ID)
	if !ok || relationship != sdk.DependencyRelationshipTransitive || directTarget != "a-00" {
		t.Fatalf("diamond placement = (%q, %q, %t)", relationship, directTarget, ok)
	}
}

func TestValidateHintsSanitizesAndBoundsAdvice(t *testing.T) {
	graph := sdk.New()
	dependency := testDependency(
		"dependency",
		"pkg:npm/dependency@1.0.0",
		sdk.DependencyRelationshipTransitive,
		sdk.DependencySourceRegistry,
	)
	if err := graph.AddNode(dependency); err != nil {
		t.Fatal(err)
	}
	detection := sdk.DetectionResult{
		DetectorName: "test-detector",
		Graphs: sdk.SingleGraphContainer(
			graph,
			sdk.ManifestMetadata{Path: "package-lock.json"},
		),
	}
	descriptor := sdk.DetectorDescriptor{
		Name:              "test-detector",
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
		RemediationCapabilities: []sdk.RemediationCapability{{
			SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Actions:           []sdk.RemediationAction{sdk.RemediationActionTransitiveOverride},
		}},
	}
	rawAdvice := "\x1b[31m" + strings.Repeat("x", maxDetectorAdviceRunes+100) + "\nspoofed"
	validated, rejected := validateHints(detection, descriptor, []sdk.RemediationHint{{
		DependencyRef: dependency.ID,
		ManifestPath:  "package-lock.json",
		Strategies: []sdk.RemediationStrategyHint{{
			Action: sdk.RemediationActionTransitiveOverride,
			Advice: rawAdvice,
		}},
	}})
	if len(rejected) != 0 || len(validated) != 1 {
		t.Fatalf("validateHints() = %#v, %#v", validated, rejected)
	}
	advice := validated[0].strategies[sdk.RemediationActionTransitiveOverride]
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
	detection := sdk.DetectionResult{DetectorName: "test-detector"}
	detector := remediationTestDetector{
		descriptor: sdk.DetectorDescriptor{
			Name: "test-detector",
			RemediationCapabilities: []sdk.RemediationCapability{{
				SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Actions:           []sdk.RemediationAction{sdk.RemediationActionDirectBump},
			}},
		},
		response: sdk.RemediationHintResponse{Diagnostics: diagnostics},
	}
	_, warnings := collectHints(context.Background(), Input{
		Registry:   sdk.NewPackageRegistry(),
		Detections: []sdk.DetectionResult{detection, detection},
		Detectors:  map[string]sdk.Detector{"test-detector": detector},
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

func overrideHint(dependencyRef, manifestPath string) sdk.RemediationHint {
	return sdk.RemediationHint{
		DependencyRef: dependencyRef,
		ManifestPath:  manifestPath,
		Strategies: []sdk.RemediationStrategyHint{{
			Action: sdk.RemediationActionTransitiveOverride,
			Advice: "use the package manager override field",
		}},
	}
}

func TestDeriveRejectsUnadvertisedAndUnknownHints(t *testing.T) {
	graph := sdk.New()
	dependency := testDependency("direct", "pkg:npm/direct@1.0.0", sdk.DependencyRelationshipDirect, sdk.DependencySourceRegistry)
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: dependency.Coordinates,
		Vulnerabilities: []sdk.Vulnerability{{
			ID:      "VULN-1",
			FixedIn: "1.2.0",
		}},
	})
	detection := sdk.DetectionResult{
		DetectorName: "test-detector",
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    graph,
			Manifest: sdk.ManifestMetadata{Path: "package-lock.json"},
		}}},
	}
	detector := remediationTestDetector{
		descriptor: sdk.DetectorDescriptor{
			Name: "test-detector",
			RemediationCapabilities: []sdk.RemediationCapability{{
				SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Actions:           []sdk.RemediationAction{sdk.RemediationActionDirectBump},
			}},
		},
		response: sdk.RemediationHintResponse{Hints: []sdk.RemediationHint{
			{
				DependencyRef: "missing",
				ManifestPath:  "package-lock.json",
				Strategies: []sdk.RemediationStrategyHint{{
					Action: sdk.RemediationActionDirectBump,
				}},
			},
			{
				DependencyRef: "direct",
				ManifestPath:  "package-lock.json",
				Strategies: []sdk.RemediationStrategyHint{{
					Action: sdk.RemediationActionTransitiveOverride,
				}},
			},
		}},
	}
	warnings := Derive(context.Background(), Input{
		Registry: registry,
		Manifests: []sdk.ConsolidatedManifest{{
			Entry:        detection.Graphs.Entries[0],
			DetectorName: detection.DetectorName,
		}},
		Detections: []sdk.DetectionResult{detection},
		Detectors:  map[string]sdk.Detector{"test-detector": detector},
	})
	if len(warnings) != 2 {
		t.Fatalf("Derive() warnings = %#v, want 2", warnings)
	}
	assertSuggestion(t, registry, dependency.PackageRef, sdk.RemediationActionManualReview, dependency.ID, "")
}

func TestDeriveResolvesRebasedHintAndWarnsWhenManifestResolutionFails(t *testing.T) {
	const (
		purl         = "pkg:npm/example@1.0.0"
		manifestPath = "package-lock.json"
	)
	detectionGraph := sdk.New()
	rawDependency := sdk.NewDependencyWithID("raw-lockfile-id", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			PURL: purl, Name: "example", Version: "1.0.0",
			PackageManager: sdk.PackageManagerNPM,
		},
		ID:           "raw-lockfile-id",
		Relationship: sdk.DependencyRelationshipDirect,
		Source:       sdk.DependencySourceRegistry,
	})
	if err := detectionGraph.AddNode(rawDependency); err != nil {
		t.Fatal(err)
	}
	detection := sdk.DetectionResult{
		DetectorName: "test-detector",
		Graphs: sdk.SingleGraphContainer(
			detectionGraph,
			sdk.ManifestMetadata{Path: manifestPath},
		),
	}
	detector := remediationTestDetector{
		descriptor: sdk.DetectorDescriptor{
			Name:              "test-detector",
			SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			RemediationCapabilities: []sdk.RemediationCapability{{
				SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Actions:           []sdk.RemediationAction{sdk.RemediationActionDirectBump},
			}},
		},
		response: sdk.RemediationHintResponse{Hints: []sdk.RemediationHint{{
			DependencyRef: rawDependency.ID,
			ManifestPath:  manifestPath,
			Strategies: []sdk.RemediationStrategyHint{{
				Action: sdk.RemediationActionDirectBump,
			}},
		}}},
	}

	newRegistry := func() *sdk.PackageRegistry {
		registry := sdk.NewPackageRegistry()
		registry.Add(&sdk.Package{
			Coordinates: sdk.Coordinates{
				PURL: purl, Name: "example", Version: "1.0.0",
			},
			Vulnerabilities: []sdk.Vulnerability{{ID: "VULN-1", FixedIn: "1.2.0"}},
		})
		return registry
	}

	t.Run("rebased dependency id", func(t *testing.T) {
		consolidated := sdk.New()
		rebased := testDependency(
			purl,
			purl,
			sdk.DependencyRelationshipDirect,
			sdk.DependencySourceRegistry,
		)
		if err := consolidated.AddNode(rebased); err != nil {
			t.Fatal(err)
		}
		registry := newRegistry()
		warnings := Derive(context.Background(), Input{
			Registry: registry,
			Manifests: []sdk.ConsolidatedManifest{{
				DetectorName: detection.DetectorName,
				Entry: sdk.GraphEntry{
					Graph: consolidated, Manifest: sdk.ManifestMetadata{Path: manifestPath},
				},
			}},
			Detections: []sdk.DetectionResult{detection},
			Detectors:  map[string]sdk.Detector{"test-detector": detector},
		})
		if len(warnings) != 0 {
			t.Fatalf("Derive() warnings = %#v", warnings)
		}
		assertSuggestion(t, registry, purl, sdk.RemediationActionDirectBump, purl, "")
	})

	t.Run("unresolved consolidated manifest", func(t *testing.T) {
		registry := newRegistry()
		warnings := Derive(context.Background(), Input{
			Registry: registry,
			Manifests: []sdk.ConsolidatedManifest{{
				DetectorName: detection.DetectorName,
				Entry: sdk.GraphEntry{
					Graph: sdk.New(), Manifest: sdk.ManifestMetadata{Path: manifestPath},
				},
			}},
			Detections: []sdk.DetectionResult{detection},
			Detectors:  map[string]sdk.Detector{"test-detector": detector},
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
	graph := sdk.New()
	dependency := testDependency("direct", "pkg:npm/direct@1.0.0", sdk.DependencyRelationshipDirect, sdk.DependencySourceRegistry)
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: dependency.Coordinates,
		Vulnerabilities: []sdk.Vulnerability{{
			ID:      "VULN-1",
			FixedIn: "1.2.0",
		}},
	})
	detection := sdk.DetectionResult{
		DetectorName: "test-detector",
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    graph,
			Manifest: sdk.ManifestMetadata{Path: "package-lock.json"},
		}}},
	}
	detector := remediationTestDetector{
		descriptor: sdk.DetectorDescriptor{
			Name: "test-detector",
			RemediationCapabilities: []sdk.RemediationCapability{{
				SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Actions:           []sdk.RemediationAction{sdk.RemediationActionDirectBump},
			}},
		},
		err: errors.New("provider failed"),
	}
	warnings := Derive(context.Background(), Input{
		Registry: registry,
		Manifests: []sdk.ConsolidatedManifest{{
			Entry:        detection.Graphs.Entries[0],
			DetectorName: detection.DetectorName,
		}},
		Detections: []sdk.DetectionResult{detection},
		Detectors:  map[string]sdk.Detector{"test-detector": detector},
	})
	if len(warnings) != 1 || warnings[0].Message != "provider failed" {
		t.Fatalf("Derive() warnings = %#v", warnings)
	}
	assertSuggestion(t, registry, dependency.PackageRef, sdk.RemediationActionManualReview, dependency.ID, "")
}

func testDependency(id, purl string, relationship sdk.DependencyRelationship, source sdk.DependencySource) *sdk.Dependency {
	return sdk.NewDependencyWithID(id, sdk.Dependency{
		Coordinates: sdk.Coordinates{
			PURL:           purl,
			Name:           id,
			Version:        "1.0.0",
			PackageManager: sdk.PackageManagerNPM,
			Type:           sdk.PackageTypePackage,
		},
		ID:           id,
		Relationship: relationship,
		Source:       source,
		PackageRef:   purl,
	})
}

func assertSuggestion(
	t *testing.T,
	registry *sdk.PackageRegistry,
	purl string,
	action sdk.RemediationAction,
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
