package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestNormalizeGraphPackageIdentity_CollapsesEquivalentPythonPackages(t *testing.T) {
	g := sdk.New()
	root := sdk.NewDependencyWithID("app@1.0.0", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "app", Version: "1.0.0"}})
	pyA := sdk.NewDependencyWithID("Requests_Toolbelt@1.0.0RC1", sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "python", Name: "Requests_Toolbelt", Version: "1.0.0RC1"}})
	pyB := sdk.NewDependencyWithID("requests-toolbelt@1.0.0rc1", sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "python", Name: "requests-toolbelt", Version: "1.0.0rc1"}})
	for _, pkg := range []*sdk.Dependency{root, pyA, pyB} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("AddPackage(%q) error = %v", pkg.ID, err)
		}
	}
	if err := g.AddEdge(root.ID, pyA.ID); err != nil {
		t.Fatalf("AddDependency(pyA) error = %v", err)
	}
	if err := g.AddEdge(root.ID, pyB.ID); err != nil {
		t.Fatalf("AddDependency(pyB) error = %v", err)
	}

	normalized, err := normalizeGraphPackageIdentity(g)
	if err != nil {
		t.Fatalf("normalizeGraphPackageIdentity() error = %v", err)
	}

	if normalized.Size() != 2 {
		t.Fatalf("expected duplicate python packages to collapse to 2 nodes, got %d", normalized.Size())
	}
	depID := "pkg:pypi/requests-toolbelt@1.0.0rc1"
	dep, ok := normalized.Node(depID)
	if !ok {
		t.Fatalf("expected normalized python package %q", depID)
	}
	deps, err := normalized.DirectDependencies("pkg:generic/app@1.0.0")
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0].ID != dep.ID {
		t.Fatalf("expected single collapsed dependency %q, got %#v", dep.ID, deps)
	}
	if dep.Metadata == nil {
		t.Fatal("expected normalization metadata on collapsed dependency")
	}
}

func TestNormalizeGraphPackageIdentity_NormalizesScopedNPMPackage(t *testing.T) {
	g := graphFixture(
		[]nodeFixture{{id: "@Types/Node@20.11.30", name: "@Types/Node", version: "20.11.30"}},
		nil,
	)
	pkg, _ := g.Node("@Types/Node@20.11.30")
	pkg.Ecosystem = "npm"

	normalized, err := normalizeGraphPackageIdentity(g)
	if err != nil {
		t.Fatalf("normalizeGraphPackageIdentity() error = %v", err)
	}
	if _, ok := normalized.Node("pkg:npm/%40types/node@20.11.30"); !ok {
		t.Fatal("expected scoped npm package to normalize to canonical namespace and name")
	}
}

func TestConsolidateGraphs_PreservesManifestRoots(t *testing.T) {
	npmGraph := graphFixture(
		[]nodeFixture{{id: "web-app@1.0.0", name: "web-app", version: "1.0.0"}, {id: "react@18.2.0", name: "react", version: "18.2.0"}},
		[][2]string{{"web-app@1.0.0", "react@18.2.0"}},
	)
	goGraph := graphFixture(
		[]nodeFixture{{id: "example.com/api", name: "example.com/api"}, {id: "rsc.io/quote@v1.5.2", name: "rsc.io/quote", version: "v1.5.2"}},
		[][2]string{{"example.com/api", "rsc.io/quote@v1.5.2"}},
	)

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		{SubprojectInfo: sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"}, RelativePath: "apps/web", PrimaryDetector: "npm-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM}, Ecosystem: sdk.EcosystemNPM}, DetectorName: "npm-detector", Graphs: sdk.SingleGraphContainer(npmGraph, sdk.ManifestMetadata{Path: "apps/web/package-lock.json", Kind: "package-lock.json"})},
		{SubprojectInfo: sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"}, RelativePath: "services/api", PrimaryDetector: "go-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerGoMod}, Ecosystem: sdk.EcosystemGo}, DetectorName: "go-detector", Graphs: sdk.SingleGraphContainer(goGraph, sdk.ManifestMetadata{Path: "services/api/go.mod", Kind: "go.mod"})},
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	if consolidated.Graphs == nil {
		t.Fatal("expected consolidated graph container")
	}
	if len(consolidated.Subprojects) != 2 {
		t.Fatalf("expected 2 consolidated subprojects, got %d", len(consolidated.Subprojects))
	}
	if len(consolidated.Graphs.Entries) != 2 {
		t.Fatalf("expected 2 consolidated graph entries, got %d", len(consolidated.Graphs.Entries))
	}
	mergedGraph, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if _, ok := mergedGraph.Node("subproject:npm:apps/web"); ok {
		t.Fatal("did not expect synthetic npm subproject root")
	}
	if _, ok := mergedGraph.Node("subproject:gomod:services/api"); ok {
		t.Fatal("did not expect synthetic go subproject root")
	}

	if _, ok := mergedGraph.Node("apps/web/package-lock.json"); ok {
		t.Fatal("did not expect manifest node in merged graph")
	}
	if _, ok := mergedGraph.Node("pkg:generic/web-app@1.0.0"); !ok {
		t.Fatal("expected normalized project root package in merged graph")
	}

	if len(consolidated.Subprojects[0].RootManifestIDs) == 0 {
		t.Fatal("expected consolidated subproject manifest roots")
	}
}

func TestConsolidateGraphs_RejectsMultipleExecutionTargets(t *testing.T) {
	_, err := ConsolidateGraphs([]sdk.DetectionResult{
		{SubprojectInfo: sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo-a"}, RelativePath: ".", PrimaryDetector: "npm-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM}, Ecosystem: sdk.EcosystemNPM}, Graphs: sdk.SingleGraphContainer(graphFixture(nil, nil), sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
		{SubprojectInfo: sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo-b"}, RelativePath: ".", PrimaryDetector: "go-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerGoMod}, Ecosystem: sdk.EcosystemGo}, Graphs: sdk.SingleGraphContainer(graphFixture(nil, nil), sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
	})
	if err == nil {
		t.Fatal("expected error for multiple execution targets")
	}
}

func TestConsolidateGraphs_DeduplicatesManifestAndPrefersNative(t *testing.T) {
	nativeGraph := sdk.New()
	nativeRoot := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "maven", Org: "org.owasp.webgoat", Name: "webgoat", Version: "1.0.0"}})
	nativeDep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "maven", Org: "org.slf4j", Name: "slf4j-api", Version: "2.0.9"}})
	if err := nativeGraph.AddNode(nativeRoot); err != nil {
		t.Fatalf("add native root: %v", err)
	}
	if err := nativeGraph.AddNode(nativeDep); err != nil {
		t.Fatalf("add native dep: %v", err)
	}
	if err := nativeGraph.AddEdge(nativeRoot.ID, nativeDep.ID); err != nil {
		t.Fatalf("add native dependency: %v", err)
	}

	syftGraph := sdk.New()
	syftRoot := sdk.NewDependencyWithID("1234567890123456", sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "maven", Org: "org.owasp.webgoat", Name: "webgoat", Version: "1.0.0", PURL: "pkg:maven/org.owasp.webgoat/webgoat@1.0.0"}})
	if err := syftGraph.AddNode(syftRoot); err != nil {
		t.Fatalf("add syft root: %v", err)
	}

	projectRoot := "C:/Users/ahmed/repos/examples/WebGoat"
	manifestAbs := projectRoot + "/pom.xml"

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		{
			SubprojectInfo: sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: projectRoot}, RelativePath: ".", PrimaryDetector: "maven-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerMaven}, Ecosystem: sdk.EcosystemMaven},
			DetectorName:   "syft-detector",
			Origin:         sdk.BundledOrigin,
			Technique:      sdk.MultipleTechnique,
			Graphs:         sdk.SingleGraphContainer(syftGraph, sdk.ManifestMetadata{Path: manifestAbs, Kind: "pom.xml"}),
		},
		{
			SubprojectInfo: sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: projectRoot}, RelativePath: ".", PrimaryDetector: "maven-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerMaven}, Ecosystem: sdk.EcosystemMaven},
			DetectorName:   "maven-detector",
			Origin:         sdk.CoreOrigin,
			Technique:      sdk.BuildToolTechnique,
			Graphs:         sdk.SingleGraphContainer(nativeGraph, sdk.ManifestMetadata{Path: manifestAbs, Kind: "pom.xml"}),
		},
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	if len(consolidated.Graphs.Entries) != 1 {
		t.Fatalf("expected 1 deduplicated manifest entry, got %d", len(consolidated.Graphs.Entries))
	}
	entry := consolidated.Graphs.Entries[0]
	if entry.Manifest.Path != "pom.xml" {
		t.Fatalf("expected relative native manifest path pom.xml, got %q", entry.Manifest.Path)
	}
	if len(consolidated.Subprojects) != 1 || consolidated.Subprojects[0].DetectorName != "maven-detector" {
		t.Fatalf("expected native detector metadata after dedup, got %#v", consolidated.Subprojects)
	}

	mergedGraph, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if _, ok := mergedGraph.Node("pkg:maven/org.owasp.webgoat/webgoat@1.0.0"); !ok {
		t.Fatal("expected native root ID to be normalized to purl")
	}
	if _, ok := mergedGraph.Node("pkg:maven/org.slf4j/slf4j-api@2.0.9"); !ok {
		t.Fatal("expected native dependency ID to be normalized to purl")
	}
}

func TestManifestDedupPriorityPrefersNativeOverSyft(t *testing.T) {
	if got := ManifestDedupPriority(sdk.CoreOrigin); got != 1 {
		t.Fatalf("expected core build-tool detector priority 1, got %d", got)
	}
	if got := ManifestDedupPriority(sdk.BundledOrigin); got != 2 {
		t.Fatalf("expected bundled multiple-technique detector priority 2, got %d", got)
	}
	if ManifestDedupPriority(sdk.CoreOrigin) >= ManifestDedupPriority(sdk.BundledOrigin) {
		t.Fatal("expected core detector to outrank bundled multiple-technique detector for manifest deduplication")
	}
}

func TestConsolidateGraphs_SynthesizesManifestRootWhenEntryHasMultipleRoots(t *testing.T) {
	actionsGraph := sdk.New()
	checkout := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "github-actions", Name: "actions/checkout", Version: "v4.1.6"}})
	setupJava := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "github-actions", Name: "actions/setup-java", Version: "v5"}})
	if err := actionsGraph.AddNode(checkout); err != nil {
		t.Fatalf("add checkout: %v", err)
	}
	if err := actionsGraph.AddNode(setupJava); err != nil {
		t.Fatalf("add setup-java: %v", err)
	}

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
			RelativePath:            ".github/actions/java-setup",
			PrimaryDetector:         "github-actions-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerGitHubActions},
			Ecosystem:               sdk.EcosystemGitHub,
		},
		DetectorName: "syft-detector",
		Graphs: sdk.SingleGraphContainer(actionsGraph, sdk.ManifestMetadata{
			Path: ".github/actions/java-setup",
			Kind: "github-actions",
		}),
	}})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}

	mergedGraph, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	virtualRootID := ".github/actions/java-setup"
	virtualRoot, ok := mergedGraph.Node(virtualRootID)
	if !ok {
		t.Fatalf("expected synthesized virtual root package %q", virtualRootID)
	}
	if virtualRoot.Type != "manifest" {
		t.Fatalf("expected virtual root type manifest, got %q", virtualRoot.Type)
	}

	deps, err := mergedGraph.DirectDependencies(virtualRootID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected virtual root to point to 2 action roots, got %d", len(deps))
	}
}

func TestConsolidateGraphs_PrefersApplicationRootWhenEntryHasMultipleRoots(t *testing.T) {
	npmGraph := sdk.New()
	app := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "demo-app", Version: "1.0.0", Type: sdk.PackageTypeApplication}})
	react := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "react", Version: "18.2.0"}})
	orphan := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "string-width", Version: "2.1.1"}})
	for _, pkg := range []*sdk.Dependency{app, react, orphan} {
		if err := npmGraph.AddNode(pkg); err != nil {
			t.Fatalf("add %s: %v", pkg.ID, err)
		}
	}
	if err := npmGraph.AddEdge(app.ID, react.ID); err != nil {
		t.Fatalf("link app->react: %v", err)
	}

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Graphs: sdk.SingleGraphContainer(npmGraph, sdk.ManifestMetadata{
			Path: "package-lock.json",
			Kind: "package-lock.json",
		}),
	}})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}

	if len(consolidated.Manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(consolidated.Manifests))
	}
	if consolidated.Manifests[0].RootManifestID != "pkg:npm/demo-app@1.0.0" {
		t.Fatalf("expected root manifest ID to be application package, got %q", consolidated.Manifests[0].RootManifestID)
	}

	mergedGraph, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if _, ok := mergedGraph.Node("package-lock.json"); ok {
		t.Fatal("did not expect synthesized manifest package for npm graph with application root")
	}

	deps, err := mergedGraph.DirectDependencies("pkg:npm/demo-app@1.0.0")
	if err != nil {
		t.Fatalf("Dependencies(app) error = %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected application root to depend on both original roots, got %d", len(deps))
	}
}

type nodeFixture struct {
	id      string
	name    string
	version string
}

func graphFixture(packages []nodeFixture, relationships [][2]string) *sdk.Graph {
	g := sdk.New()
	for _, pkg := range packages {
		if err := g.AddNode(sdk.NewDependencyRefWithID(pkg.id, pkg.name, pkg.version)); err != nil {
			panic(err)
		}
	}
	for _, relationship := range relationships {
		if err := g.AddEdge(relationship[0], relationship[1]); err != nil {
			panic(err)
		}
	}
	return g
}

func TestConsolidateGraphs_KeepsSameManifestNameAcrossSubprojects(t *testing.T) {
	rootTarget := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"}
	serviceGraph := graphFixture(
		[]nodeFixture{{id: "svc@1.0.0", name: "svc", version: "1.0.0"}},
		nil,
	)
	harnessGraph := graphFixture(
		[]nodeFixture{{id: "harness@1.0.0", name: "harness", version: "1.0.0"}},
		nil,
	)

	// Two nested subprojects that each emit a manifest named requirements.txt
	// in their own coordinate space. Consolidation must rebase both onto the
	// repository root instead of collapsing them into one dedup key.
	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		{
			SubprojectInfo:      sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/repo/fixtures/service"}, RelativePath: "fixtures/service", PrimaryDetector: "python-pip", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerPip}, Ecosystem: sdk.EcosystemPython},
			RootExecutionTarget: rootTarget,
			DetectorName:        "python-pip",
			Origin:              sdk.CoreOrigin,
			Graphs:              sdk.SingleGraphContainer(serviceGraph, sdk.ManifestMetadata{Path: "requirements.txt", Kind: "pip"}),
		},
		{
			SubprojectInfo:      sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/repo/harness"}, RelativePath: "harness", PrimaryDetector: "python-pip", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerPip}, Ecosystem: sdk.EcosystemPython},
			RootExecutionTarget: rootTarget,
			DetectorName:        "python-pip",
			Origin:              sdk.CoreOrigin,
			Graphs:              sdk.SingleGraphContainer(harnessGraph, sdk.ManifestMetadata{Path: "requirements.txt", Kind: "pip"}),
		},
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	if len(consolidated.Graphs.Entries) != 2 {
		t.Fatalf("expected both same-named manifests to survive dedup, got %d entries", len(consolidated.Graphs.Entries))
	}
	paths := []string{consolidated.Graphs.Entries[0].Manifest.Path, consolidated.Graphs.Entries[1].Manifest.Path}
	want := map[string]bool{"fixtures/service/requirements.txt": true, "harness/requirements.txt": true}
	for _, p := range paths {
		if !want[p] {
			t.Fatalf("expected repo-relative manifest paths, got %v", paths)
		}
	}
}

func TestConsolidateGraphs_AcceptsNestedSubprojectExecutionTargets(t *testing.T) {
	// Nested subprojects carry their own ExecutionTarget locations; the
	// multiple-execution-target guard must key on RootExecutionTarget (stamped
	// by the resolve stage), not the per-subproject targets.
	rootTarget := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"}
	_, err := ConsolidateGraphs([]sdk.DetectionResult{
		{
			SubprojectInfo:      sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/repo/apps/web"}, RelativePath: "apps/web", PrimaryDetector: "npm-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM}, Ecosystem: sdk.EcosystemNPM},
			RootExecutionTarget: rootTarget,
			Graphs:              sdk.SingleGraphContainer(graphFixture([]nodeFixture{{id: "web@1.0.0", name: "web", version: "1.0.0"}}, nil), sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
		},
		{
			SubprojectInfo:      sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/repo/services/api"}, RelativePath: "services/api", PrimaryDetector: "go-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerGoMod}, Ecosystem: sdk.EcosystemGo},
			RootExecutionTarget: rootTarget,
			Graphs:              sdk.SingleGraphContainer(graphFixture([]nodeFixture{{id: "api", name: "api"}}, nil), sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"}),
		},
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v; nested subproject targets must not trip the multi-target guard", err)
	}
}

func TestConsolidateGraphs_SharedDependencyAcrossModuleEntriesCountsOnce(t *testing.T) {
	// Two module entries from one workspace resolution share a transitive
	// dependency. The consolidated graph must contain it once.
	shared := sdk.NewDependencyWithID("shared@2.0.0", sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "shared", Version: "2.0.0"}})
	webRoot := sdk.NewDependencyWithID("web@1.0.0", sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "web", Version: "1.0.0", Type: sdk.PackageTypeApplication}})
	libRoot := sdk.NewDependencyWithID("lib@1.0.0", sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "lib", Version: "1.0.0", Type: sdk.PackageTypeApplication}})

	webGraph := sdk.New()
	for _, pkg := range []*sdk.Dependency{webRoot, shared} {
		if err := webGraph.AddNode(pkg); err != nil {
			t.Fatalf("add web node: %v", err)
		}
	}
	if err := webGraph.AddEdge(webRoot.ID, shared.ID); err != nil {
		t.Fatalf("add web edge: %v", err)
	}
	libGraph := sdk.New()
	for _, pkg := range []*sdk.Dependency{libRoot, shared} {
		if err := libGraph.AddNode(pkg); err != nil {
			t.Fatalf("add lib node: %v", err)
		}
	}
	if err := libGraph.AddEdge(libRoot.ID, shared.ID); err != nil {
		t.Fatalf("add lib edge: %v", err)
	}

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"}, RelativePath: ".", PrimaryDetector: "npm-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM}, Ecosystem: sdk.EcosystemNPM},
		DetectorName:   "npm-detector",
		Origin:         sdk.CoreOrigin,
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{
			{Graph: webGraph, Manifest: sdk.ManifestMetadata{Path: "apps/web/package.json", Kind: "package.json"}},
			{Graph: libGraph, Manifest: sdk.ManifestMetadata{Path: "packages/lib/package.json", Kind: "package.json"}},
		}},
	}})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	if len(consolidated.Graphs.Entries) != 2 {
		t.Fatalf("expected both module manifests to survive, got %d", len(consolidated.Graphs.Entries))
	}
	merged, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	sharedCount := 0
	for _, pkg := range merged.Nodes() {
		if pkg != nil && pkg.Name == "shared" {
			sharedCount++
		}
	}
	if sharedCount != 1 {
		t.Fatalf("expected shared dependency once in merged graph, got %d", sharedCount)
	}
}
