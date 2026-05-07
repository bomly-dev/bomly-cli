package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestNormalizeGraphPackageIdentity_CollapsesEquivalentPythonPackages(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackageWithID("app@1.0.0", sdk.Package{Name: "app", Version: "1.0.0"})
	pyA := sdk.NewPackageWithID("Requests_Toolbelt@1.0.0RC1", sdk.Package{Ecosystem: "python", Name: "Requests_Toolbelt", Version: "1.0.0RC1"})
	pyB := sdk.NewPackageWithID("requests-toolbelt@1.0.0rc1", sdk.Package{Ecosystem: "python", Name: "requests-toolbelt", Version: "1.0.0rc1"})
	for _, pkg := range []*sdk.Package{root, pyA, pyB} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("AddPackage(%q) error = %v", pkg.ID, err)
		}
	}
	if err := g.AddDependency(root.ID, pyA.ID); err != nil {
		t.Fatalf("AddDependency(pyA) error = %v", err)
	}
	if err := g.AddDependency(root.ID, pyB.ID); err != nil {
		t.Fatalf("AddDependency(pyB) error = %v", err)
	}

	normalized, err := normalizeGraphPackageIdentity(g)
	if err != nil {
		t.Fatalf("normalizeGraphPackageIdentity() error = %v", err)
	}

	if normalized.Size() != 2 {
		t.Fatalf("expected duplicate python packages to collapse to 2 nodes, got %d", normalized.Size())
	}
	depID := "pkg:python/requests-toolbelt@1.0.0rc1"
	dep, ok := normalized.Package(depID)
	if !ok {
		t.Fatalf("expected normalized python package %q", depID)
	}
	deps, err := normalized.Dependencies("pkg:generic/app@1.0.0")
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
	pkg, _ := g.Package("@Types/Node@20.11.30")
	pkg.Ecosystem = "npm"

	normalized, err := normalizeGraphPackageIdentity(g)
	if err != nil {
		t.Fatalf("normalizeGraphPackageIdentity() error = %v", err)
	}
	if _, ok := normalized.Package("pkg:npm/types/node@20.11.30"); !ok {
		t.Fatal("expected scoped npm package to normalize to lowercase namespace and name")
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
	if _, ok := mergedGraph.Package("subproject:npm:apps/web"); ok {
		t.Fatal("did not expect synthetic npm subproject root")
	}
	if _, ok := mergedGraph.Package("subproject:gomod:services/api"); ok {
		t.Fatal("did not expect synthetic go subproject root")
	}

	if _, ok := mergedGraph.Package("apps/web/package-lock.json"); ok {
		t.Fatal("did not expect manifest node in merged graph")
	}
	if _, ok := mergedGraph.Package("pkg:generic/web-app@1.0.0"); !ok {
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
	nativeRoot := sdk.NewPackage(sdk.Package{Ecosystem: "maven", Org: "org.owasp.webgoat", Name: "webgoat", Version: "1.0.0"})
	nativeDep := sdk.NewPackage(sdk.Package{Ecosystem: "maven", Org: "org.slf4j", Name: "slf4j-api", Version: "2.0.9"})
	if err := nativeGraph.AddPackage(nativeRoot); err != nil {
		t.Fatalf("add native root: %v", err)
	}
	if err := nativeGraph.AddPackage(nativeDep); err != nil {
		t.Fatalf("add native dep: %v", err)
	}
	if err := nativeGraph.AddDependency(nativeRoot.ID, nativeDep.ID); err != nil {
		t.Fatalf("add native dependency: %v", err)
	}

	syftGraph := sdk.New()
	syftRoot := sdk.NewPackageWithID("1234567890123456", sdk.Package{Ecosystem: "maven", Org: "org.owasp.webgoat", Name: "webgoat", Version: "1.0.0", PURL: "pkg:maven/org.owasp.webgoat/webgoat@1.0.0"})
	if err := syftGraph.AddPackage(syftRoot); err != nil {
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
	if _, ok := mergedGraph.Package("pkg:maven/org.owasp.webgoat/webgoat@1.0.0"); !ok {
		t.Fatal("expected native root ID to be normalized to purl")
	}
	if _, ok := mergedGraph.Package("pkg:maven/org.slf4j/slf4j-api@2.0.9"); !ok {
		t.Fatal("expected native dependency ID to be normalized to purl")
	}
}

func TestManifestDedupPriorityPrefersNativeOverSyft(t *testing.T) {
	if got := ManifestDedupPriority(sdk.CoreOrigin, sdk.BuildToolTechnique); got != 1 {
		t.Fatalf("expected core build-tool detector priority 1, got %d", got)
	}
	if got := ManifestDedupPriority(sdk.BundledOrigin, sdk.MultipleTechnique); got != 2 {
		t.Fatalf("expected bundled multiple-technique detector priority 2, got %d", got)
	}
	if !(ManifestDedupPriority(sdk.CoreOrigin, sdk.BuildToolTechnique) < ManifestDedupPriority(sdk.BundledOrigin, sdk.MultipleTechnique)) {
		t.Fatal("expected core detector to outrank bundled multiple-technique detector for manifest deduplication")
	}
}

func TestConsolidateGraphs_SynthesizesManifestRootWhenEntryHasMultipleRoots(t *testing.T) {
	actionsGraph := sdk.New()
	checkout := sdk.NewPackage(sdk.Package{Ecosystem: "github-actions", Name: "actions/checkout", Version: "v4.1.6"})
	setupJava := sdk.NewPackage(sdk.Package{Ecosystem: "github-actions", Name: "actions/setup-java", Version: "v5"})
	if err := actionsGraph.AddPackage(checkout); err != nil {
		t.Fatalf("add checkout: %v", err)
	}
	if err := actionsGraph.AddPackage(setupJava); err != nil {
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
	virtualRoot, ok := mergedGraph.Package(virtualRootID)
	if !ok {
		t.Fatalf("expected synthesized virtual root package %q", virtualRootID)
	}
	if virtualRoot.Type != "manifest" {
		t.Fatalf("expected virtual root type manifest, got %q", virtualRoot.Type)
	}

	deps, err := mergedGraph.Dependencies(virtualRootID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected virtual root to point to 2 action roots, got %d", len(deps))
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
		if err := g.AddPackage(sdk.NewPackageRefWithID(pkg.id, pkg.name, pkg.version)); err != nil {
			panic(err)
		}
	}
	for _, relationship := range relationships {
		if err := g.AddDependency(relationship[0], relationship[1]); err != nil {
			panic(err)
		}
	}
	return g
}
