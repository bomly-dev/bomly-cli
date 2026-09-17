package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// Two spellings of one Python package -- name case and separators, and a
// release-candidate version written in a different case -- mint the same
// identity, so the second insertion folds into the first and the consumer's
// edges point at one node.
//
// The version half came back with bomly-sdk v0.9.2, which canonicalizes a
// PyPI version per PEP 440 before minting. It was briefly untrue: v0.9.0
// stopped lowercasing every version containing a letter, which was right --
// that rule corrupted Maven's "1.0-SNAPSHOT" -- and cost this fold until the
// ecosystem-correct rule replaced the blanket one.
//
// Normalization moved into the constructor with ADR-0041, which is why this
// case no longer builds two nodes and then collapses them: the second node
// never exists.
func TestEquivalentPythonSpellingsFoldOnInsertion(t *testing.T) {
	g := model.New()
	root := testnodes.Ref("app", "1.0.0")
	pyA := testnodes.Dep(model.Coordinates{Ecosystem: "python", Name: "Requests_Toolbelt", Version: "1.0.0RC1"})
	pyB := testnodes.Dep(model.Coordinates{Ecosystem: "python", Name: "requests-toolbelt", Version: "1.0.0rc1"})

	const want = "pkg:pypi/requests-toolbelt@1.0.0rc1"
	if pyA.NodeID() != want || pyB.NodeID() != want {
		t.Fatalf("identities = %q and %q, want both to mint %q", pyA.NodeID(), pyB.NodeID(), want)
	}
	for _, pkg := range []*model.DependencyNode{root, pyA, pyB} {
		if _, err := g.InsertNode(pkg); err != nil {
			t.Fatalf("InsertNode(%q) error = %v", pkg.NodeID(), err)
		}
	}
	if err := g.AddEdge(root.NodeID(), pyA.NodeID()); err != nil {
		t.Fatalf("AddEdge(pyA) error = %v", err)
	}
	if err := g.AddEdge(root.NodeID(), pyB.NodeID()); err != nil {
		t.Fatalf("AddEdge(pyB) error = %v", err)
	}

	normalized, err := normalizeGraphPackageIdentity(g)
	if err != nil {
		t.Fatalf("normalizeGraphPackageIdentity() error = %v", err)
	}
	if normalized.Size() != 2 {
		t.Fatalf("graph size = %d, want the root plus one folded package", normalized.Size())
	}
	deps, err := normalized.DirectDependencies(root.NodeID())
	if err != nil {
		t.Fatalf("DirectDependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0].NodeID() != want {
		t.Fatalf("root dependencies = %#v, want the one folded package", deps)
	}
}

// A scoped npm name is canonicalized into namespace and name by the same
// constructor gate, so the identity is percent-encoded exactly as the purl
// spec requires.
func TestScopedNPMNameMintsTheCanonicalIdentity(t *testing.T) {
	pkg := testnodes.Dep(model.Coordinates{Ecosystem: "npm", Name: "@Types/Node", Version: "20.11.30"})
	if pkg.NodeID() != "pkg:npm/%40types/node@20.11.30" {
		t.Fatalf("identity = %q, want the canonical scoped npm package URL", pkg.NodeID())
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

	consolidated, err := ConsolidateGraphs([]plugin.DetectionResult{
		{SubprojectInfo: plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo"}, RelativePath: "apps/web", PrimaryDetector: "npm-detector", DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM}, Ecosystem: model.EcosystemNPM}, DetectorName: "npm-detector", Graphs: model.SingleGraphContainer(npmGraph, model.ManifestMetadata{Path: "apps/web/package-lock.json", Kind: "package-lock.json"})},
		{SubprojectInfo: plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo"}, RelativePath: "services/api", PrimaryDetector: "go-detector", DetectedPackageManagers: []model.PackageManager{model.PackageManagerGoMod}, Ecosystem: model.EcosystemGo}, DetectorName: "go-detector", Graphs: model.SingleGraphContainer(goGraph, model.ManifestMetadata{Path: "services/api/go.mod", Kind: "go.mod"})},
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
	if _, ok := testnodes.Find(mergedGraph, "subproject:npm:apps/web"); ok {
		t.Fatal("did not expect synthetic npm subproject root")
	}
	if _, ok := testnodes.Find(mergedGraph, "subproject:gomod:services/api"); ok {
		t.Fatal("did not expect synthetic go subproject root")
	}

	if _, ok := testnodes.Find(mergedGraph, "apps/web/package-lock.json"); ok {
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
	_, err := ConsolidateGraphs([]plugin.DetectionResult{
		{SubprojectInfo: plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo-a"}, RelativePath: ".", PrimaryDetector: "npm-detector", DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM}, Ecosystem: model.EcosystemNPM}, Graphs: model.SingleGraphContainer(graphFixture(nil, nil), model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
		{SubprojectInfo: plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo-b"}, RelativePath: ".", PrimaryDetector: "go-detector", DetectedPackageManagers: []model.PackageManager{model.PackageManagerGoMod}, Ecosystem: model.EcosystemGo}, Graphs: model.SingleGraphContainer(graphFixture(nil, nil), model.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
	})
	if err == nil {
		t.Fatal("expected error for multiple execution targets")
	}
}

func TestConsolidateGraphs_DeduplicatesManifestAndPrefersNative(t *testing.T) {
	nativeGraph := model.New()
	nativeRoot := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "maven", Org: "org.owasp.webgoat", Name: "webgoat", Version: "1.0.0"}})
	nativeDep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "maven", Org: "org.slf4j", Name: "slf4j-api", Version: "2.0.9"}})
	if err := nativeGraph.AddNode(nativeRoot); err != nil {
		t.Fatalf("add native root: %v", err)
	}
	if err := nativeGraph.AddNode(nativeDep); err != nil {
		t.Fatalf("add native dep: %v", err)
	}
	if err := nativeGraph.AddEdge(nativeRoot.NodeID(), nativeDep.NodeID()); err != nil {
		t.Fatalf("add native dependency: %v", err)
	}

	syftGraph := model.New()
	syftRoot := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "maven", Org: "org.owasp.webgoat", Name: "webgoat", Version: "1.0.0", PURL: "pkg:maven/org.owasp.webgoat/webgoat@1.0.0"}})
	if err := syftGraph.AddNode(syftRoot); err != nil {
		t.Fatalf("add syft root: %v", err)
	}

	projectRoot := "C:/Users/ahmed/repos/examples/WebGoat"
	manifestAbs := projectRoot + "/pom.xml"

	consolidated, err := ConsolidateGraphs([]plugin.DetectionResult{
		{
			SubprojectInfo: plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: projectRoot}, RelativePath: ".", PrimaryDetector: "maven-detector", DetectedPackageManagers: []model.PackageManager{model.PackageManagerMaven}, Ecosystem: model.EcosystemMaven},
			DetectorName:   "syft-detector",
			Origin:         plugin.BundledOrigin,
			Technique:      plugin.MultipleTechnique,
			Graphs:         model.SingleGraphContainer(syftGraph, model.ManifestMetadata{Path: manifestAbs, Kind: "pom.xml"}),
		},
		{
			SubprojectInfo: plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: projectRoot}, RelativePath: ".", PrimaryDetector: "maven-detector", DetectedPackageManagers: []model.PackageManager{model.PackageManagerMaven}, Ecosystem: model.EcosystemMaven},
			DetectorName:   "maven-detector",
			Origin:         plugin.CoreOrigin,
			Technique:      plugin.BuildToolTechnique,
			Graphs:         model.SingleGraphContainer(nativeGraph, model.ManifestMetadata{Path: manifestAbs, Kind: "pom.xml"}),
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
	if got := ManifestDedupPriority(plugin.CoreOrigin); got != 1 {
		t.Fatalf("expected core build-tool detector priority 1, got %d", got)
	}
	if got := ManifestDedupPriority(plugin.BundledOrigin); got != 2 {
		t.Fatalf("expected bundled multiple-technique detector priority 2, got %d", got)
	}
	if ManifestDedupPriority(plugin.CoreOrigin) >= ManifestDedupPriority(plugin.BundledOrigin) {
		t.Fatal("expected core detector to outrank bundled multiple-technique detector for manifest deduplication")
	}
}

func TestConsolidateGraphs_SynthesizesManifestRootWhenEntryHasMultipleRoots(t *testing.T) {
	actionsGraph := model.New()
	checkout := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "github-actions", Name: "actions/checkout", Version: "v4.1.6"}})
	setupJava := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "github-actions", Name: "actions/setup-java", Version: "v5"}})
	if err := actionsGraph.AddNode(checkout); err != nil {
		t.Fatalf("add checkout: %v", err)
	}
	if err := actionsGraph.AddNode(setupJava); err != nil {
		t.Fatalf("add setup-java: %v", err)
	}

	consolidated, err := ConsolidateGraphs([]plugin.DetectionResult{{
		SubprojectInfo: plugin.Subproject{
			ExecutionTarget:         plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo"},
			RelativePath:            ".github/actions/java-setup",
			PrimaryDetector:         "github-actions-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerGitHubActions},
			Ecosystem:               model.EcosystemGitHub,
		},
		DetectorName: "syft-detector",
		Graphs: model.SingleGraphContainer(actionsGraph, model.ManifestMetadata{
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

	// A synthesized root standing in for a manifest is a manifest node now,
	// not a dependency node typed "manifest" (ADR-0041).
	virtualRootID := ".github/actions/java-setup"
	virtualRoot, ok := testnodes.Find(mergedGraph, virtualRootID)
	if !ok {
		t.Fatalf("expected a synthesized root for %q", virtualRootID)
	}
	if virtualRoot.Kind() != model.NodeKindManifest {
		t.Fatalf("synthesized root is a %s node, want a manifest node", virtualRoot.Kind())
	}

	deps, err := mergedGraph.DirectDependencies(testnodes.ID(mergedGraph, virtualRootID))
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected virtual root to point to 2 action roots, got %d", len(deps))
	}
}

func TestConsolidateGraphs_PrefersApplicationRootWhenEntryHasMultipleRoots(t *testing.T) {
	npmGraph := model.New()
	app := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "npm", Name: "demo-app", Version: "1.0.0", Type: model.PackageTypeApplication}})
	react := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "npm", Name: "react", Version: "18.2.0"}})
	orphan := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "npm", Name: "string-width", Version: "2.1.1"}})
	for _, pkg := range []*model.DependencyNode{app, react, orphan} {
		if err := npmGraph.AddNode(pkg); err != nil {
			t.Fatalf("add %s: %v", pkg.NodeID(), err)
		}
	}
	if err := npmGraph.AddEdge(app.NodeID(), react.NodeID()); err != nil {
		t.Fatalf("link app->react: %v", err)
	}

	consolidated, err := ConsolidateGraphs([]plugin.DetectionResult{{
		SubprojectInfo: plugin.Subproject{
			ExecutionTarget:         plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Graphs: model.SingleGraphContainer(npmGraph, model.ManifestMetadata{
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
	if _, ok := testnodes.Find(mergedGraph, "package-lock.json"); ok {
		t.Fatal("did not expect synthesized manifest package for npm graph with application root")
	}

	deps, err := mergedGraph.DirectDependencies("pkg:npm/demo-app@1.0.0")
	if err != nil {
		t.Fatalf("Dependencies(app) error = %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected application root to depend on both original roots, got %d", len(deps))
	}
	orphanNode, ok := mergedGraph.DependencyNode("pkg:npm/string-width@2.1.1")
	if !ok {
		t.Fatal("expected orphan dependency to remain in the graph")
	}
	if orphanNode.Relationship != model.DependencyRelationshipUnknown {
		t.Fatalf("orphan relationship = %q, want unknown", orphanNode.Relationship)
	}
}

type nodeFixture struct {
	id      string
	name    string
	version string
}

func graphFixture(packages []nodeFixture, relationships [][2]string) *model.Graph {
	g := model.New()
	for _, pkg := range packages {
		if err := g.AddNode(testnodes.Ref(pkg.name, pkg.version)); err != nil {
			panic(err)
		}
	}
	for _, relationship := range relationships {
		// Resolved from the label the fixture names, because a node ID is a
		// canonical package URL now (ADR-0041).
		from := testnodes.ID(g, relationship[0])
		to := testnodes.ID(g, relationship[1])
		if err := g.AddEdge(from, to); err != nil {
			panic(err)
		}
	}
	return g
}

func TestConsolidateGraphs_KeepsSameManifestNameAcrossSubprojects(t *testing.T) {
	rootTarget := plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo"}
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
	consolidated, err := ConsolidateGraphs([]plugin.DetectionResult{
		{
			SubprojectInfo:      plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetFilesystem, Location: "/repo/fixtures/service"}, RelativePath: "fixtures/service", PrimaryDetector: "python-pip", DetectedPackageManagers: []model.PackageManager{model.PackageManagerPip}, Ecosystem: model.EcosystemPython},
			RootExecutionTarget: rootTarget,
			DetectorName:        "python-pip",
			Origin:              plugin.CoreOrigin,
			Graphs:              model.SingleGraphContainer(serviceGraph, model.ManifestMetadata{Path: "requirements.txt", Kind: "pip"}),
		},
		{
			SubprojectInfo:      plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetFilesystem, Location: "/repo/harness"}, RelativePath: "harness", PrimaryDetector: "python-pip", DetectedPackageManagers: []model.PackageManager{model.PackageManagerPip}, Ecosystem: model.EcosystemPython},
			RootExecutionTarget: rootTarget,
			DetectorName:        "python-pip",
			Origin:              plugin.CoreOrigin,
			Graphs:              model.SingleGraphContainer(harnessGraph, model.ManifestMetadata{Path: "requirements.txt", Kind: "pip"}),
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
	rootTarget := plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo"}
	_, err := ConsolidateGraphs([]plugin.DetectionResult{
		{
			SubprojectInfo:      plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetFilesystem, Location: "/repo/apps/web"}, RelativePath: "apps/web", PrimaryDetector: "npm-detector", DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM}, Ecosystem: model.EcosystemNPM},
			RootExecutionTarget: rootTarget,
			Graphs:              model.SingleGraphContainer(graphFixture([]nodeFixture{{id: "web@1.0.0", name: "web", version: "1.0.0"}}, nil), model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
		},
		{
			SubprojectInfo:      plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetFilesystem, Location: "/repo/services/api"}, RelativePath: "services/api", PrimaryDetector: "go-detector", DetectedPackageManagers: []model.PackageManager{model.PackageManagerGoMod}, Ecosystem: model.EcosystemGo},
			RootExecutionTarget: rootTarget,
			Graphs:              model.SingleGraphContainer(graphFixture([]nodeFixture{{id: "api", name: "api"}}, nil), model.ManifestMetadata{Path: "go.mod", Kind: "go.mod"}),
		},
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v; nested subproject targets must not trip the multi-target guard", err)
	}
}

func TestConsolidateGraphs_SharedDependencyAcrossModuleEntriesCountsOnce(t *testing.T) {
	// Two module entries from one workspace resolution share a transitive
	// dependency. The consolidated graph must contain it once.
	shared := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "npm", Name: "shared", Version: "2.0.0"}})
	webRoot := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "npm", Name: "web", Version: "1.0.0", Type: model.PackageTypeApplication}})
	libRoot := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "npm", Name: "lib", Version: "1.0.0", Type: model.PackageTypeApplication}})

	webGraph := model.New()
	for _, pkg := range []*model.DependencyNode{webRoot, shared} {
		if err := webGraph.AddNode(pkg); err != nil {
			t.Fatalf("add web node: %v", err)
		}
	}
	if err := webGraph.AddEdge(webRoot.NodeID(), shared.NodeID()); err != nil {
		t.Fatalf("add web edge: %v", err)
	}
	libGraph := model.New()
	for _, pkg := range []*model.DependencyNode{libRoot, shared} {
		if err := libGraph.AddNode(pkg); err != nil {
			t.Fatalf("add lib node: %v", err)
		}
	}
	if err := libGraph.AddEdge(libRoot.NodeID(), shared.NodeID()); err != nil {
		t.Fatalf("add lib edge: %v", err)
	}

	consolidated, err := ConsolidateGraphs([]plugin.DetectionResult{{
		SubprojectInfo: plugin.Subproject{ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo"}, RelativePath: ".", PrimaryDetector: "npm-detector", DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM}, Ecosystem: model.EcosystemNPM},
		DetectorName:   "npm-detector",
		Origin:         plugin.CoreOrigin,
		Graphs: &model.GraphContainer{Entries: []model.GraphEntry{
			{Graph: webGraph, Manifest: model.ManifestMetadata{Path: "apps/web/package.json", Kind: "package.json"}},
			{Graph: libGraph, Manifest: model.ManifestMetadata{Path: "packages/lib/package.json", Kind: "package.json"}},
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
	for _, pkg := range merged.DependencyNodes() {
		if pkg != nil && pkg.Name == "shared" {
			sharedCount++
		}
	}
	if sharedCount != 1 {
		t.Fatalf("expected shared dependency once in merged graph, got %d", sharedCount)
	}
}
