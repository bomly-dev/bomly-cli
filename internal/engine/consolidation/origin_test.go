package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/nodes"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	sdk "github.com/bomly-dev/bomly-sdk"
)

// This file used to pin the occurrence machinery: a package resolved from two
// places became two nodes with minted, origin-derived IDs, and most of these
// cases were about keeping those IDs apart and order-free.
//
// ADR-0041 removed all of it. Identity is the canonical package URL, so two
// records that resolved one name@version from different places are one node,
// and the disagreement is kept where it can be read -- the node's Origins
// list, union-merged. The properties worth pinning changed with it: not "how
// many nodes", but "does the fold lose anything".

// artifactOrigins builds the origin list an artifact URL asserts, or nothing
// when the URL is not one the publication gates accept.
func artifactOrigins(artifactURL string) []sdk.DependencyOrigin {
	origin := sdk.ArtifactOrigin(artifactURL)
	if origin == nil {
		return nil
	}
	return []sdk.DependencyOrigin{*origin}
}

// repositoryOrigins builds the origin list a repository and revision assert,
// or nothing when they are not a pair the publication gates accept.
func repositoryOrigins(repository, revision string) []sdk.DependencyOrigin {
	origin := sdk.RepositoryOrigin(repository, revision)
	if origin == nil {
		return nil
	}
	return []sdk.DependencyOrigin{*origin}
}

// subprojectResult builds one manifest's detection result carrying a single
// package whose origin the caller chooses.
func subprojectResult(t *testing.T, relativePath, manifest, artifactURL string) sdk.DetectionResult {
	t.Helper()

	g := sdk.New()
	pkg := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
		Name: "lodash", Version: "4.17.21", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lodash@4.17.21"}})
	if artifactURL != "" {
		pkg.Origins = sdk.MergeOrigins(nil, artifactOrigins(artifactURL))
	}
	if err := g.AddNode(pkg); err != nil {
		t.Fatal(err)
	}
	return sdk.DetectionResult{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
			RelativePath:            relativePath,
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Graphs:       sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: manifest, Kind: "package-lock.json"}),
	}
}

// graphIDs lists node ids for failure messages.
func graphIDs(g *sdk.Graph) []string {
	var ids []string
	g.WalkNodes(func(node sdk.GraphNode) bool {
		ids = append(ids, node.NodeID())
		return true
	})
	return ids
}

// nodesNamed returns every dependency node with a given name.
func nodesNamed(g *sdk.Graph, name string) []*sdk.DependencyNode {
	var found []*sdk.DependencyNode
	g.WalkDependencyNodes(func(dep *sdk.DependencyNode) bool {
		if dep.Name == name {
			found = append(found, dep)
		}
		return true
	})
	return found
}

// artifactURLs lists the artifact URLs a node's origins assert.
func artifactURLs(dep *sdk.DependencyNode) map[string]int {
	urls := map[string]int{}
	for _, origin := range dep.Origins {
		urls[origin.ArtifactURL]++
	}
	return urls
}

// Two subprojects resolving one package from two mirrors used to produce two
// nodes. They produce one, because a PURL says nothing about where a package
// came from and two nodes with identical identity are the duplicate-identity
// problem ADR-0041 removed. Neither resolution is lost: both are on the node.
func TestConsolidateGraphsFoldsContradictingResolutionsKeepingBoth(t *testing.T) {
	const (
		a = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		b = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		subprojectResult(t, "apps/one", "apps/one/package-lock.json", a),
		subprojectResult(t, "apps/two", "apps/two/package-lock.json", b),
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	merged, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	found := nodesNamed(merged, "lodash")
	if len(found) != 1 {
		t.Fatalf("lodash nodes = %d (%v), want one node per identity", len(found), graphIDs(merged))
	}
	if got := found[0].NodeID(); got != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("lodash node ID = %q, want the canonical package URL", got)
	}
	urls := artifactURLs(found[0])
	if urls[a] != 1 || urls[b] != 1 {
		t.Fatalf("lodash origins = %v, want both resolutions recorded once each", urls)
	}
}

// The fold is a set union, so a repeated witness adds nothing and the answer
// does not depend on the order the manifests were walked in.
func TestConsolidateGraphsFoldIsOrderFreeAndDeduplicated(t *testing.T) {
	const (
		a = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		b = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	for _, order := range [][3]string{{a, b, b}, {b, a, b}, {b, b, a}} {
		t.Run(order[0][8:16]+"-first", func(t *testing.T) {
			consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
				subprojectResult(t, "apps/one", "apps/one/package-lock.json", order[0]),
				subprojectResult(t, "apps/two", "apps/two/package-lock.json", order[1]),
				subprojectResult(t, "apps/three", "apps/three/package-lock.json", order[2]),
			})
			if err != nil {
				t.Fatalf("ConsolidateGraphs() error = %v", err)
			}
			merged, err := consolidated.Graphs.ConsolidatedGraph()
			if err != nil {
				t.Fatalf("ConsolidatedGraph() error = %v", err)
			}

			found := nodesNamed(merged, "lodash")
			if len(found) != 1 {
				t.Fatalf("lodash nodes = %d (%v), want one", len(found), graphIDs(merged))
			}
			urls := artifactURLs(found[0])
			if len(urls) != 2 || urls[a] != 1 || urls[b] != 1 {
				t.Fatalf("lodash origins = %v, want each distinct resolution exactly once", urls)
			}
		})
	}
}

// A record with no publishable origin -- a registry resolution the gates
// reject, say -- must not erase the origin another record asserted. This is
// the failure the fill-gap merge class exists to prevent: an empty value
// counting as a stated one.
func TestConsolidateGraphsOriginFreeRecordKeepsTheAssertedOrigin(t *testing.T) {
	const artifact = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		subprojectResult(t, "apps/one", "apps/one/package-lock.json", ""),
		subprojectResult(t, "apps/two", "apps/two/package-lock.json", artifact),
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	merged, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	found := nodesNamed(merged, "lodash")
	if len(found) != 1 {
		t.Fatalf("lodash nodes = %d (%v), want one", len(found), graphIDs(merged))
	}
	if urls := artifactURLs(found[0]); urls[artifact] != 1 {
		t.Fatalf("lodash origins = %v, want the asserted resolution kept", urls)
	}
}

// A project-owned record never folds with an external one, even when both name
// the same package: the project's own artifact is a module node, and a module
// ID is not a package URL. That separation is what keeps the project's
// component from publishing an origin it never had -- a uv editable project
// consumed as a git dependency by a sibling is the case in the wild.
func TestProjectRecordsNeverFoldWithMatchingExternalResolutions(t *testing.T) {
	const purl = "pkg:pypi/helper@1.0.0"

	projectGraph := sdk.New()
	projectRoot := testnodes.ModuleFrom("pyproject.toml", sdk.Coordinates{
		Name: "helper", Version: "1.0.0", Ecosystem: sdk.EcosystemPython,
		PURL: purl, Type: sdk.PackageTypeApplication,
	})
	if err := projectGraph.AddNode(projectRoot); err != nil {
		t.Fatal(err)
	}

	externalGraph := sdk.New()
	external := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
		Name: "helper", Version: "1.0.0", Ecosystem: sdk.EcosystemPython, PURL: purl}})
	external.Origins = sdk.MergeOrigins(nil, repositoryOrigins(
		"https://github.com/other/helper", "aaaabbbbccccddddeeeeffff0000111122223333"))
	if err := externalGraph.AddNode(external); err != nil {
		t.Fatal(err)
	}

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
				RelativePath:    "helper", Ecosystem: sdk.EcosystemPython,
			},
			DetectorName: "uv-detector",
			Graphs: sdk.SingleGraphContainer(projectGraph,
				sdk.ManifestMetadata{Path: "helper/pyproject.toml", Kind: "pyproject.toml"}),
		},
		{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
				RelativePath:    "consumer", Ecosystem: sdk.EcosystemPython,
			},
			DetectorName: "uv-detector",
			Graphs: sdk.SingleGraphContainer(externalGraph,
				sdk.ManifestMetadata{Path: "consumer/uv.lock", Kind: "uv.lock"}),
		},
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	merged, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	var projectNodes, externalNodes int
	merged.WalkNodes(func(node sdk.GraphNode) bool {
		name, _, _, _ := nodes.Display(node)
		if name != "helper" {
			return true
		}
		if nodes.IsProjectOwned(node) {
			projectNodes++
			return true
		}
		externalNodes++
		dep, _ := nodes.AsDependency(node)
		if dep == nil || len(dep.Origins) == 0 {
			t.Errorf("the external record lost the repository it resolved from")
		}
		return true
	})
	if projectNodes != 1 || externalNodes != 1 {
		t.Fatalf("helper nodes = %d project / %d external (%v), want one of each",
			projectNodes, externalNodes, graphIDs(merged))
	}
}

// When two records witness one resolution, the fold must keep both witnesses'
// usage facts. Scopes, locations, and relationship aggregate onto the
// surviving node instead of vanishing with whichever record lost the walk
// order -- which is the whole reason folding is safe.
func TestConsolidateGraphsFoldedWitnessesKeepUsageFacts(t *testing.T) {
	const artifact = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"

	record := func(t *testing.T, relativePath, manifest string, scope sdk.Scope,
		relationship sdk.DependencyRelationship, location string) sdk.DetectionResult {
		t.Helper()
		result := subprojectResult(t, relativePath, manifest, artifact)
		graph := result.Graphs.Entries[0].Graph
		for _, dep := range graph.DependencyNodes() {
			dep.AddScope(scope)
			dep.Relationship = relationship
			dep.Locations = []sdk.PackageLocation{{RealPath: location, AccessPath: location}}
		}
		return result
	}

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		record(t, "apps/one", "apps/one/package-lock.json",
			sdk.ScopeDevelopment, sdk.DependencyRelationshipTransitive, "apps/one/package-lock.json"),
		record(t, "apps/two", "apps/two/package-lock.json",
			sdk.ScopeRuntime, sdk.DependencyRelationshipDirect, "apps/two/package-lock.json"),
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	merged, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	found := nodesNamed(merged, "lodash")
	if len(found) != 1 {
		t.Fatalf("lodash nodes = %d (%v), want one", len(found), graphIDs(merged))
	}
	survivor := found[0]
	if !survivor.HasScope(sdk.ScopeRuntime) || !survivor.HasScope(sdk.ScopeDevelopment) {
		t.Errorf("scopes = %v, want the union of both witnesses", survivor.Scopes)
	}
	if survivor.Relationship != sdk.DependencyRelationshipDirect {
		t.Errorf("relationship = %q, want the stronger claim to survive", survivor.Relationship)
	}
	if len(survivor.Locations) != 2 {
		t.Errorf("locations = %v, want both witnesses' locations", survivor.Locations)
	}
}

// One manifest can record a package twice -- a Bun lockfile listing one name
// and version from two mirrors under distinct per-entry keys. Those fold too:
// the rule is about identity, not about which graph the records arrived in.
func TestConsolidateGraphsFoldsDuplicatesWithinOneManifest(t *testing.T) {
	const (
		a = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		b = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	g := sdk.New()
	for _, url := range []string{a, b} {
		pkg := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
			Name: "lodash", Version: "4.17.21", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lodash@4.17.21"}})
		pkg.Origins = sdk.MergeOrigins(nil, artifactOrigins(url))
		if _, err := g.InsertNode(pkg); err != nil {
			t.Fatal(err)
		}
	}

	normalized, err := normalizeGraphPackageIdentity(g)
	if err != nil {
		t.Fatalf("normalizeGraphPackageIdentity() error = %v", err)
	}
	found := nodesNamed(normalized, "lodash")
	if len(found) != 1 {
		t.Fatalf("lodash nodes = %d (%v), want one", len(found), graphIDs(normalized))
	}
	if urls := artifactURLs(found[0]); urls[a] != 1 || urls[b] != 1 {
		t.Fatalf("lodash origins = %v, want both mirrors recorded", urls)
	}
}
