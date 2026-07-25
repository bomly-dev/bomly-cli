package engine_test

import (
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/engine/consolidation"
	explainengine "github.com/bomly-dev/bomly-cli/internal/engine/explain"
	"github.com/bomly-dev/bomly-cli/internal/mcp"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestCanonicalGraphFixturePreservesOccurrenceAndPackageAccounting(t *testing.T) {
	consolidated := canonicalAccountingFixture(t)
	registry := consolidation.BuildPackageRegistry(consolidated)
	merged, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	const (
		wantOccurrences = 12
		wantPackages    = 11
		wantDirect      = 7
		wantTransitive  = 1
		wantUnknown     = 1
		wantStructural  = 2
		wantEligible    = 5
	)

	occurrences := 0
	for _, entry := range consolidated.Graphs.Entries {
		occurrences += entry.Graph.Size()
	}
	if occurrences != wantOccurrences {
		t.Fatalf("manifest occurrences = %d, want %d", occurrences, wantOccurrences)
	}
	if merged.Size() != wantPackages || registry.Len() != wantPackages {
		t.Fatalf("deduplicated graph/registry = %d/%d, want %d", merged.Size(), registry.Len(), wantPackages)
	}

	var direct, transitive, unknown, structural, eligible int
	for _, dependency := range merged.Nodes() {
		if dependency.FirstParty || dependency.Type == sdk.PackageTypeManifest {
			structural++
		} else {
			switch dependency.Relationship {
			case sdk.DependencyRelationshipDirect:
				direct++
			case sdk.DependencyRelationshipTransitive:
				transitive++
			case sdk.DependencyRelationshipUnknown:
				unknown++
			default:
				t.Errorf("non-structural dependency %q has no relationship", dependency.ID)
			}
		}
		if dependency.RegistryMatchEligible() {
			eligible++
		}
		if dependency.PackageRef == "" || dependency.PackageRef != sdk.CanonicalPackageURLFromDependency(dependency) {
			t.Errorf("dependency %q package_ref = %q", dependency.ID, dependency.PackageRef)
		} else if _, ok := registry.Get(dependency.PackageRef); !ok {
			t.Errorf("dependency %q does not join to registry package %q", dependency.ID, dependency.PackageRef)
		}
	}
	if direct != wantDirect || transitive != wantTransitive || unknown != wantUnknown || structural != wantStructural {
		t.Fatalf("relationship accounting direct/transitive/unknown/structural = %d/%d/%d/%d, want %d/%d/%d/%d",
			direct, transitive, unknown, structural, wantDirect, wantTransitive, wantUnknown, wantStructural)
	}
	if direct+transitive+unknown+structural != merged.Size() {
		t.Fatalf("relationship accounting covers %d nodes, graph has %d", direct+transitive+unknown+structural, merged.Size())
	}
	if eligible != wantEligible || eligible+(merged.Size()-eligible) != merged.Size() {
		t.Fatalf("eligibility accounting eligible/ineligible = %d/%d, want %d/%d",
			eligible, merged.Size()-eligible, wantEligible, wantPackages-wantEligible)
	}

	assertOccurrenceSpecificFacts(t, consolidated, registry, merged)
	assertUnknownSyntheticParentIsNotExecutableEvidence(t, merged)
	assertStructuredAndCompactAccounting(t, consolidated, registry, merged, wantOccurrences, wantPackages)
	assertExplainAndDiffAccounting(t, consolidated, registry, merged, wantPackages)
}

func canonicalAccountingFixture(t *testing.T) sdk.ConsolidatedGraph {
	t.Helper()
	first := sdk.New()
	app := accountingDependency("app", "1.0.0", sdk.PackageTypeApplication, sdk.DependencySourceProject, "")
	app.FirstParty = true
	actual := accountingDependency("actual", "1.0.0", "", sdk.DependencySourceRegistry, sdk.DependencyRelationshipDirect)
	actual.Scopes = sdk.ScopesOf(sdk.ScopeRuntime)
	actual.Metadata = map[string]any{sdk.MetadataKeyNPM: &sdk.NPMPackageMetadata{
		PeerDependencies:         map[string]string{"peer": "^2.0.0"},
		OptionalPeerDependencies: []string{"peer"},
	}}
	parent := accountingDependency("parent", "2.0.0", "", sdk.DependencySourceRegistry, sdk.DependencyRelationshipDirect)
	duplicateV1 := accountingDependency("duplicate", "1.0.0", "", sdk.DependencySourceRegistry, sdk.DependencyRelationshipTransitive)
	duplicateV1.Scopes = sdk.ScopesOf(sdk.ScopeDevelopment)
	orphan := accountingDependency("orphan", "3.0.0", "", sdk.DependencySourceRegistry, sdk.DependencyRelationshipUnknown)
	gitDependency := accountingDependency("git-lib", "4.0.0", "", sdk.DependencySourceGit, sdk.DependencyRelationshipDirect)
	workspace := accountingDependency("workspace-lib", "1.0.0", sdk.PackageTypeApplication, sdk.DependencySourceWorkspace, sdk.DependencyRelationshipDirect)
	duplicateV2 := accountingDependency("duplicate", "2.0.0", "", sdk.DependencySourceRegistry, sdk.DependencyRelationshipDirect)
	for _, dependency := range []*sdk.Dependency{app, actual, parent, duplicateV1, orphan, gitDependency, workspace, duplicateV2} {
		if err := first.AddNode(dependency); err != nil {
			t.Fatalf("add first graph node: %v", err)
		}
	}
	for _, edge := range [][2]string{
		{app.ID, actual.ID},
		{app.ID, parent.ID},
		{parent.ID, duplicateV1.ID},
		{app.ID, gitDependency.ID},
		{app.ID, workspace.ID},
		{app.ID, duplicateV2.ID},
	} {
		if err := first.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add first graph edge: %v", err)
		}
	}

	second := sdk.New()
	tool := accountingDependency("tool", "1.0.0", sdk.PackageTypeApplication, sdk.DependencySourceProject, "")
	tool.FirstParty = true
	actualAgain := accountingDependency("actual", "1.0.0", "", sdk.DependencySourceRegistry, sdk.DependencyRelationshipDirect)
	fileDependency := accountingDependency("file-lib", "1.0.0", "", sdk.DependencySourceFile, sdk.DependencyRelationshipDirect)
	urlDependency := accountingDependency("url-lib", "1.0.0", "", sdk.DependencySourceURL, sdk.DependencyRelationshipDirect)
	for _, dependency := range []*sdk.Dependency{tool, actualAgain, fileDependency, urlDependency} {
		if err := second.AddNode(dependency); err != nil {
			t.Fatalf("add second graph node: %v", err)
		}
	}
	for _, dependency := range []*sdk.Dependency{actualAgain, fileDependency, urlDependency} {
		if err := second.AddEdge(tool.ID, dependency.ID); err != nil {
			t.Fatalf("add second graph edge: %v", err)
		}
	}

	result, err := consolidation.ConsolidateGraphs([]sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{
			{Graph: first, Manifest: sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}},
			{Graph: second, Manifest: sdk.ManifestMetadata{Path: "tools/package-lock.json", Kind: "package-lock.json"}},
		}},
	}})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	return result
}

func accountingDependency(name, version string, packageType sdk.PackageType, source sdk.DependencySource, relationship sdk.DependencyRelationship) *sdk.Dependency {
	return sdk.NewDependency(sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Ecosystem:      sdk.EcosystemNPM,
			PackageManager: sdk.PackageManagerNPM,
			Name:           name,
			Version:        version,
			Type:           packageType,
		},
		Source:       source,
		Relationship: relationship,
	})
}

func assertOccurrenceSpecificFacts(
	t *testing.T,
	consolidated sdk.ConsolidatedGraph,
	registry *sdk.PackageRegistry,
	graph *sdk.Graph,
) {
	t.Helper()
	const sharedPURL = "pkg:npm/actual@1.0.0"
	sharedOccurrences := 0
	runtimeOccurrences := 0
	unknownScopeOccurrences := 0
	peerMetadataOccurrences := 0
	for _, entry := range consolidated.Graphs.Entries {
		dependency, ok := entry.Graph.Node(sharedPURL)
		if !ok {
			continue
		}
		sharedOccurrences++
		switch dependency.PrimaryScope() {
		case sdk.ScopeRuntime:
			runtimeOccurrences++
		case sdk.ScopeUnknown:
			unknownScopeOccurrences++
		}
		npmMetadata, ok := dependency.Metadata[sdk.MetadataKeyNPM].(*sdk.NPMPackageMetadata)
		if ok && npmMetadata.PeerDependencies["peer"] == "^2.0.0" &&
			len(npmMetadata.OptionalPeerDependencies) == 1 &&
			npmMetadata.OptionalPeerDependencies[0] == "peer" {
			peerMetadataOccurrences++
		}
	}
	if sharedOccurrences != 2 {
		t.Fatalf("shared-PURL occurrences = %d, want 2", sharedOccurrences)
	}
	if runtimeOccurrences != 1 || unknownScopeOccurrences != 1 || peerMetadataOccurrences != 1 {
		t.Fatalf("shared occurrence scope/metadata counts runtime=%d unknown=%d peer=%d, want 1/1/1",
			runtimeOccurrences, unknownScopeOccurrences, peerMetadataOccurrences)
	}
	if _, ok := registry.Get(sharedPURL); !ok {
		t.Fatalf("shared PURL %q missing from registry", sharedPURL)
	}
	for _, purl := range []string{"pkg:npm/duplicate@1.0.0", "pkg:npm/duplicate@2.0.0"} {
		if _, ok := graph.Node(purl); !ok {
			t.Errorf("duplicate-version occurrence %q missing from graph", purl)
		}
		if _, ok := registry.Get(purl); !ok {
			t.Errorf("duplicate-version package %q missing from registry", purl)
		}
	}

	wantSources := map[string]sdk.DependencySource{
		"pkg:npm/git-lib@4.0.0":       sdk.DependencySourceGit,
		"pkg:npm/workspace-lib@1.0.0": sdk.DependencySourceWorkspace,
		"pkg:npm/file-lib@1.0.0":      sdk.DependencySourceFile,
		"pkg:npm/url-lib@1.0.0":       sdk.DependencySourceURL,
	}
	for id, want := range wantSources {
		dependency, ok := graph.Node(id)
		if !ok || dependency.Source != want {
			t.Errorf("dependency %q source = %q, found=%t, want %q", id, dependencySource(dependency), ok, want)
		}
	}
	development, ok := graph.Node("pkg:npm/duplicate@1.0.0")
	if !ok || development.PrimaryScope() != sdk.ScopeDevelopment {
		t.Fatalf("development occurrence missing or scope = %q", developmentScope(development))
	}
}

func developmentScope(dependency *sdk.Dependency) sdk.Scope {
	if dependency == nil {
		return sdk.ScopeUnknown
	}
	return dependency.PrimaryScope()
}

func dependencySource(dependency *sdk.Dependency) sdk.DependencySource {
	if dependency == nil {
		return ""
	}
	return dependency.Source
}

func assertUnknownSyntheticParentIsNotExecutableEvidence(t *testing.T, graph *sdk.Graph) {
	t.Helper()
	orphanID := "pkg:npm/orphan@3.0.0"
	paths, err := graph.CollectPathsTo(orphanID)
	if err != nil {
		t.Fatalf("CollectPathsTo(orphan) error = %v", err)
	}
	if len(paths) != 1 || len(paths[0].Nodes) != 2 {
		t.Fatalf("synthetic orphan paths = %#v", paths)
	}
	if relationship := sdk.RelationshipForPath(paths[0].Nodes); relationship != sdk.DependencyRelationshipUnknown {
		t.Fatalf("synthetic manifest ownership changed relationship to %q", relationship)
	}
}

func assertStructuredAndCompactAccounting(
	t *testing.T,
	consolidated sdk.ConsolidatedGraph,
	registry *sdk.PackageRegistry,
	graph *sdk.Graph,
	wantOccurrences, wantPackages int,
) {
	t.Helper()
	response := output.BuildScanResponse(
		output.ProjectDescriptor{Name: "fixture", Path: "/repo"},
		consolidated,
		registry,
		nil,
		time.Now(),
	)
	occurrences := 0
	for _, manifest := range response.Manifests {
		occurrences += len(manifest.Dependencies)
	}
	if occurrences != wantOccurrences {
		t.Fatalf("structured output occurrences = %d, want %d", occurrences, wantOccurrences)
	}
	if len(response.Packages) != wantPackages {
		t.Fatalf("structured output packages = %d, want %d", len(response.Packages), wantPackages)
	}

	compact := mcp.BuildCompactScan(mcp.ScanRunResult{
		Response: response,
		Graph:    graph,
		Registry: registry,
	})
	if compact.Summary.Manifests != 2 || compact.Summary.TotalPackages != wantPackages {
		t.Fatalf("compact accounting = %#v", compact.Summary)
	}
}

func assertExplainAndDiffAccounting(
	t *testing.T,
	consolidated sdk.ConsolidatedGraph,
	registry *sdk.PackageRegistry,
	graph *sdk.Graph,
	wantPackages int,
) {
	t.Helper()
	type explainCase struct {
		purl         string
		relationship sdk.DependencyRelationship
		direct       *bool
	}
	isDirect, isTransitive := true, false
	for _, test := range []explainCase{
		{purl: "pkg:npm/actual@1.0.0", relationship: sdk.DependencyRelationshipDirect, direct: &isDirect},
		{purl: "pkg:npm/duplicate@1.0.0", relationship: sdk.DependencyRelationshipTransitive, direct: &isTransitive},
		{purl: "pkg:npm/orphan@3.0.0", relationship: sdk.DependencyRelationshipUnknown},
	} {
		target, paths, err := explainengine.FindWhyPackage(graph, test.purl)
		if err != nil {
			t.Fatalf("FindWhyPackage(%q) error = %v", test.purl, err)
		}
		if len(paths) == 0 {
			t.Fatalf("FindWhyPackage(%q) returned no paths", test.purl)
		}
		for _, path := range paths {
			if path.Relationship != string(test.relationship) {
				t.Errorf("FindWhyPackage(%q) relationship = %q, want %q", test.purl, path.Relationship, test.relationship)
			}
		}
		targetResponse := output.ExplainTargetResponse{
			Project:        output.ProjectDescriptor{Name: "fixture", Path: "/repo"},
			PackageManager: sdk.PackageManagerNPM,
			Dependency: output.ExplainDependency{
				PackageRef: output.PackageFromDependencyAndRegistry(target, registry),
			},
			Paths: paths,
		}
		response := output.BuildExplainResponse(
			output.ProjectDescriptor{Name: "fixture", Path: "/repo"},
			test.purl,
			[]output.ExplainTargetResponse{targetResponse},
			time.Now(),
		)
		compact := mcp.BuildCompactExplain(test.purl, mcp.ExplainRunResult{
			Response:  response,
			Graph:     graph,
			Registry:  registry,
			Manifests: output.ScanManifestsFromConsolidated(consolidated, registry),
		})
		if len(compact.Matches) != 1 {
			t.Fatalf("compact explain matches for %q = %#v", test.purl, compact.Matches)
		}
		if test.direct == nil {
			if compact.Matches[0].Direct != nil {
				t.Errorf("compact unknown-parent directness = %v, want nil", *compact.Matches[0].Direct)
			}
		} else if compact.Matches[0].Direct == nil || *compact.Matches[0].Direct != *test.direct {
			t.Errorf("compact directness for %q = %v, want %v", test.purl, compact.Matches[0].Direct, *test.direct)
		}
	}

	base := canonicalAccountingFixture(t)
	baseRegistry := consolidation.BuildPackageRegistry(base)
	diffResponse := output.BuildDiffResponse(
		"/repo",
		"base",
		"head",
		base,
		consolidated,
		nil,
		time.Now(),
		output.ReportOptions{BaseRegistry: baseRegistry, HeadRegistry: registry},
	)
	if diffResponse.Summary.AddedManifestCount != 0 ||
		diffResponse.Summary.ChangedManifestCount != 0 ||
		diffResponse.Summary.RemovedManifestCount != 0 ||
		diffResponse.Summary.UnchangedManifestCount != 2 ||
		diffResponse.Summary.AddedPackageCount != 0 ||
		diffResponse.Summary.ChangedPackageCount != 0 ||
		diffResponse.Summary.RemovedPackageCount != 0 {
		t.Fatalf("identical graph diff summary = %#v", diffResponse.Summary)
	}
	if len(diffResponse.Packages) != wantPackages {
		t.Fatalf("diff registry union packages = %d, want %d", len(diffResponse.Packages), wantPackages)
	}
	compactDiff := mcp.BuildCompactDiff(mcp.DiffRunResult{
		Response:     diffResponse,
		HeadGraph:    graph,
		HeadRegistry: registry,
		BaseRegistry: baseRegistry,
	})
	if compactDiff.Summary.ManifestsAdded != 0 ||
		compactDiff.Summary.ManifestsChanged != 0 ||
		compactDiff.Summary.ManifestsRemoved != 0 ||
		compactDiff.Summary.PackagesAdded != 0 ||
		compactDiff.Summary.PackagesChanged != 0 ||
		compactDiff.Summary.PackagesRemoved != 0 {
		t.Fatalf("compact identical diff summary = %#v", compactDiff.Summary)
	}
}
