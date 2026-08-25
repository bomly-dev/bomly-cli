package consolidation

import (
	"fmt"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

// originOf returns the origin a node publishes, or the zero value when it has
// none, so cases can compare plain structs.
func originOf(dep *sdk.Dependency) sdk.DependencyOrigin {
	if dep == nil {
		return sdk.DependencyOrigin{}
	}
	if origin := dep.Origin.Normalized(); origin != nil {
		return *origin
	}
	return sdk.DependencyOrigin{}
}

// subprojectResult builds one manifest's detection result carrying a single
// package whose origin the caller chooses.
func subprojectResult(t *testing.T, relativePath, manifest, artifactURL string) sdk.DetectionResult {
	t.Helper()

	g := sdk.New()
	pkg := sdk.NewDependencyWithID("lodash@4.17.21", sdk.Dependency{Coordinates: sdk.Coordinates{
		Name: "lodash", Version: "4.17.21", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lodash@4.17.21"}})
	if artifactURL != "" {
		pkg.Origin = sdk.ArtifactOrigin(artifactURL)
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
	g.WalkNodes(func(dep *sdk.Dependency) bool {
		ids = append(ids, dep.ID)
		return true
	})
	return ids
}

// Each manifest is resolved on its own, so a package two subprojects share
// arrives as two records. Two witnesses of one resolution fold; a gap fills;
// and a contradiction survives as two nodes, each in its own manifest's graph
// position -- no tiebreak ever picks a winner.
func TestConsolidateGraphsPreservesContradictingOccurrences(t *testing.T) {
	const (
		public  = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		private = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	cases := []struct {
		name  string
		left  string
		right string
		want  map[string]int // artifact URL -> node count in the merged graph
	}{
		{
			name: "subprojects agree",
			left: public, right: public,
			want: map[string]int{public: 1},
		},
		{
			name: "one subproject recorded nothing",
			left: public, right: "",
			want: map[string]int{public: 1},
		},
		{
			name: "a gap fills regardless of order",
			left: "", right: public,
			want: map[string]int{public: 1},
		},
		{
			name: "subprojects contradict",
			left: public, right: private,
			want: map[string]int{public: 1, private: 1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
				subprojectResult(t, "apps/web", "apps/web/package-lock.json", tc.left),
				subprojectResult(t, "services/api", "services/api/package-lock.json", tc.right),
			})
			if err != nil {
				t.Fatalf("ConsolidateGraphs() error = %v", err)
			}

			merged, err := consolidated.Graphs.ConsolidatedGraph()
			if err != nil {
				t.Fatalf("ConsolidatedGraph() error = %v", err)
			}
			got := map[string]int{}
			total := 0
			merged.WalkNodes(func(dep *sdk.Dependency) bool {
				if dep.Name != "lodash" {
					return true
				}
				total++
				if origin := originOf(dep); origin.ArtifactURL != "" {
					got[origin.ArtifactURL]++
				}
				return true
			})
			wantTotal := 0
			for _, n := range tc.want {
				wantTotal += n
			}
			if wantTotal == 0 {
				wantTotal = 1
			}
			if total != wantTotal {
				t.Fatalf("lodash nodes = %d, want %d", total, wantTotal)
			}
			for url, n := range tc.want {
				if got[url] != n {
					t.Fatalf("origins = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// Three manifests resolving origins A, B, then B must yield exactly two
// occurrences: both B witnesses land on one origin-derived occurrence ID and
// fold, whatever order the manifests are walked in.
func TestConsolidateGraphsFoldsRepeatedContradictions(t *testing.T) {
	const (
		a = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		b = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	orderings := [][3]string{{a, b, b}, {b, a, b}, {b, b, a}}
	for _, order := range orderings {
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

			origins := map[string]int{}
			var nodes int
			merged.WalkNodes(func(dep *sdk.Dependency) bool {
				if dep.Name != "lodash" {
					return true
				}
				nodes++
				origins[originOf(dep).ArtifactURL]++
				return true
			})
			if nodes != 2 || origins[a] != 1 || origins[b] != 1 {
				t.Fatalf("nodes = %d origins = %v, want exactly one occurrence per distinct origin", nodes, origins)
			}
		})
	}
}

// Occurrence identity is a pure function of (package, origin): two manifests
// carrying the same two origins in opposite positional orders must converge on
// exactly two components, one per origin, with each origin's edges folded --
// and a mixed contested/uncontested spread of the same origins must too.
func TestConsolidateGraphsOccurrenceIdentityIsOrderFree(t *testing.T) {
	const (
		a = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		b = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	// A manifest whose graph holds occurrences in the given order, built the
	// way a positional detector emits them: distinct per-entry IDs.
	multiRecord := func(t *testing.T, relativePath, manifest string, urls ...string) sdk.DetectionResult {
		t.Helper()
		g := sdk.New()
		for i, url := range urls {
			pkg := sdk.NewDependencyWithID(
				fmt.Sprintf("bun-package:lodash#%d", i),
				sdk.Dependency{Coordinates: sdk.Coordinates{
					Name: "lodash", Version: "4.17.21", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lodash@4.17.21"}},
			)
			pkg.Origin = sdk.ArtifactOrigin(url)
			if err := g.AddNode(pkg); err != nil {
				t.Fatal(err)
			}
		}
		return sdk.DetectionResult{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
				RelativePath:            relativePath,
				PrimaryDetector:         "bun-detector",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerBun},
				Ecosystem:               sdk.EcosystemNPM,
			},
			DetectorName: "bun-detector",
			Graphs:       sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: manifest, Kind: "bun.lock"}),
		}
	}

	cases := []struct {
		name    string
		results func(t *testing.T) []sdk.DetectionResult
	}{
		{name: "opposite orders", results: func(t *testing.T) []sdk.DetectionResult {
			return []sdk.DetectionResult{
				multiRecord(t, "apps/one", "apps/one/bun.lock", a, b),
				multiRecord(t, "apps/two", "apps/two/bun.lock", b, a),
			}
		}},
		{name: "mixed contested and uncontested", results: func(t *testing.T) []sdk.DetectionResult {
			return []sdk.DetectionResult{
				subprojectResult(t, "apps/one", "apps/one/package-lock.json", a),
				multiRecord(t, "apps/two", "apps/two/bun.lock", b, a),
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			consolidated, err := ConsolidateGraphs(tc.results(t))
			if err != nil {
				t.Fatalf("ConsolidateGraphs() error = %v", err)
			}
			merged, err := consolidated.Graphs.ConsolidatedGraph()
			if err != nil {
				t.Fatalf("ConsolidatedGraph() error = %v", err)
			}

			origins := map[string]int{}
			var nodes int
			merged.WalkNodes(func(dep *sdk.Dependency) bool {
				if dep.Name != "lodash" {
					return true
				}
				nodes++
				origins[originOf(dep).ArtifactURL]++
				return true
			})
			if nodes != 2 || origins[a] != 1 || origins[b] != 1 {
				t.Fatalf("nodes = %d origins = %v, want exactly one component per origin", nodes, origins)
			}
		})
	}
}

// A registry record has no publishable origin but is still a distinct
// resolution: consolidation must not re-collapse what the detector preserved,
// nor gap-fill the git origin onto it -- within one manifest or across two.
func TestConsolidationPreservesOriginFreeOccurrences(t *testing.T) {
	const gitOrigin = "https://github.com/a/helper"

	record := func(t *testing.T, id, resolvedURL string, withOrigin bool) *sdk.Dependency {
		t.Helper()
		pkg := sdk.NewDependencyWithID(id, sdk.Dependency{Coordinates: sdk.Coordinates{
			Name: "helper", Version: "1.0.0", Ecosystem: sdk.EcosystemRust, PURL: "pkg:cargo/helper@1.0.0"}})
		pkg.ResolvedURL = resolvedURL
		if withOrigin {
			pkg.Origin = sdk.RepositoryOrigin(gitOrigin, "aaaabbbbccccddddeeeeffff0000111122223333")
		}
		return pkg
	}
	result := func(t *testing.T, relativePath, manifest string, nodes ...*sdk.Dependency) sdk.DetectionResult {
		t.Helper()
		g := sdk.New()
		for _, node := range nodes {
			if err := g.AddNode(node); err != nil {
				t.Fatal(err)
			}
		}
		return sdk.DetectionResult{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
				RelativePath:            relativePath,
				PrimaryDetector:         "cargo",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerCargo},
				Ecosystem:               sdk.EcosystemRust,
			},
			DetectorName: "cargo",
			Graphs:       sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: manifest, Kind: "Cargo.lock"}),
		}
	}

	cases := []struct {
		name    string
		results func(t *testing.T) []sdk.DetectionResult
	}{
		{name: "within one manifest", results: func(t *testing.T) []sdk.DetectionResult {
			return []sdk.DetectionResult{result(t, ".", "Cargo.lock",
				record(t, "helper@1.0.0", "git+https://github.com/a/helper#aaaa", true),
				record(t, "helper@1.0.0#occ", "registry+https://github.com/rust-lang/crates.io-index", false),
			)}
		}},
		{name: "across manifests", results: func(t *testing.T) []sdk.DetectionResult {
			return []sdk.DetectionResult{
				result(t, "crates/one", "crates/one/Cargo.lock",
					record(t, "helper@1.0.0", "registry+https://github.com/rust-lang/crates.io-index", false)),
				result(t, "crates/two", "crates/two/Cargo.lock",
					record(t, "helper@1.0.0", "git+https://github.com/a/helper#aaaa", true)),
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			consolidated, err := ConsolidateGraphs(tc.results(t))
			if err != nil {
				t.Fatalf("ConsolidateGraphs() error = %v", err)
			}
			merged, err := consolidated.Graphs.ConsolidatedGraph()
			if err != nil {
				t.Fatalf("ConsolidatedGraph() error = %v", err)
			}

			var nodes, withOrigin, without int
			merged.WalkNodes(func(dep *sdk.Dependency) bool {
				if dep.Name != "helper" {
					return true
				}
				nodes++
				if origin := originOf(dep); origin.Repository == gitOrigin {
					withOrigin++
				} else if origin == (sdk.DependencyOrigin{}) {
					without++
				}
				return true
			})
			if nodes != 2 || withOrigin != 1 || without != 1 {
				t.Fatalf("nodes = %d (git %d, origin-free %d), want the registry occurrence preserved beside the git one", nodes, withOrigin, without)
			}
		})
	}
}

// A first-party project can also appear as an external dependency elsewhere
// (a uv editable project consumed as a git dependency by a sibling). The
// project's own record keeps its identity -- manifest roots must stay valid --
// while the external record is renamed away from it rather than folding in.
func TestConsolidationKeepsFirstPartyRootIdentity(t *testing.T) {
	const purl = "pkg:pypi/helper@1.0.0"

	rootGraph := sdk.New()
	projectRoot := sdk.NewDependencyWithID("helper@1.0.0", sdk.Dependency{Coordinates: sdk.Coordinates{
		Name: "helper", Version: "1.0.0", Ecosystem: sdk.EcosystemPython, PURL: purl, FirstParty: true, Type: sdk.PackageTypeApplication}})
	// Deliberately no ResolvedURL: npm workspace members clear it, and the
	// project's record must contest the external one even with no resolution
	// string of its own.
	if err := rootGraph.AddNode(projectRoot); err != nil {
		t.Fatal(err)
	}

	depGraph := sdk.New()
	gitDep := sdk.NewDependencyWithID("helper@1.0.0", sdk.Dependency{Coordinates: sdk.Coordinates{
		Name: "helper", Version: "1.0.0", Ecosystem: sdk.EcosystemPython, PURL: purl}})
	gitDep.Origin = sdk.RepositoryOrigin("https://github.com/example/helper", "aaaabbbbccccddddeeeeffff0000111122223333")
	if err := depGraph.AddNode(gitDep); err != nil {
		t.Fatal(err)
	}

	result := func(relativePath, manifest string, g *sdk.Graph, ecosystem sdk.Ecosystem) sdk.DetectionResult {
		return sdk.DetectionResult{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
				RelativePath:            relativePath,
				PrimaryDetector:         "python",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerUV},
				Ecosystem:               ecosystem,
			},
			DetectorName: "python",
			Graphs:       sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: manifest, Kind: "uv.lock"}),
		}
	}

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		result("helper", "helper/uv.lock", rootGraph, sdk.EcosystemPython),
		result("consumer", "consumer/uv.lock", depGraph, sdk.EcosystemPython),
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}

	// Every stored root ID must name a live node in its entry's graph.
	for i, manifest := range consolidated.Manifests {
		entry := consolidated.Graphs.Entries[i]
		if manifest.RootManifestID == "" || entry.Graph == nil {
			continue
		}
		if _, ok := entry.Graph.Node(manifest.RootManifestID); !ok {
			t.Fatalf("manifest %d root %q names no node in its graph", i, manifest.RootManifestID)
		}
	}

	merged, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	var firstParty, external int
	merged.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Name != "helper" {
			return true
		}
		if dep.FirstParty {
			firstParty++
			if origin := originOf(dep); origin != (sdk.DependencyOrigin{}) {
				t.Fatalf("the project's own record acquired an origin: %+v", origin)
			}
			if dep.ID != purl {
				t.Fatalf("first-party root ID = %q, want its canonical identity kept", dep.ID)
			}
		} else {
			external++
		}
		return true
	})
	if firstParty != 1 || external != 1 {
		t.Fatalf("first-party = %d external = %d, want the project and the external record distinct", firstParty, external)
	}
}

// An entry root is not always first-party (an ingested document's root, say).
// When occurrence renaming touches such a root, the stored manifest root ID
// must follow the node to its new name.
func TestConsolidationRefreshesRenamedRootIDs(t *testing.T) {
	const purl = "pkg:npm/helper@1.0.0"

	build := func(t *testing.T, repository string) *sdk.Graph {
		t.Helper()
		g := sdk.New()
		pkg := sdk.NewDependencyWithID("helper@1.0.0", sdk.Dependency{Coordinates: sdk.Coordinates{
			Name: "helper", Version: "1.0.0", Ecosystem: sdk.EcosystemNPM, PURL: purl}})
		pkg.Origin = sdk.RepositoryOrigin(repository, "aaaabbbbccccddddeeeeffff0000111122223333")
		if err := g.AddNode(pkg); err != nil {
			t.Fatal(err)
		}
		return g
	}
	result := func(relativePath, manifest string, g *sdk.Graph) sdk.DetectionResult {
		return sdk.DetectionResult{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
				RelativePath:            relativePath,
				PrimaryDetector:         "sbom",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Ecosystem:               sdk.EcosystemNPM,
			},
			DetectorName: "sbom",
			Graphs:       sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: manifest, Kind: "sbom"}),
		}
	}

	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		result("one", "one/bom.json", build(t, "https://github.com/a/helper")),
		result("two", "two/bom.json", build(t, "https://github.com/b/helper")),
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}

	for i, manifest := range consolidated.Manifests {
		entry := consolidated.Graphs.Entries[i]
		if manifest.RootManifestID == "" || entry.Graph == nil {
			continue
		}
		if _, ok := entry.Graph.Node(manifest.RootManifestID); !ok {
			t.Fatalf("manifest %d root %q names no node in its graph after renaming", i, manifest.RootManifestID)
		}
	}
	for _, subproject := range consolidated.Subprojects {
		for _, rootID := range subproject.RootManifestIDs {
			found := false
			for _, entry := range consolidated.Graphs.Entries {
				if entry.Graph == nil {
					continue
				}
				if _, ok := entry.Graph.Node(rootID); ok {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("subproject root %q names no node in any entry", rootID)
			}
		}
	}
}

// Within one manifest, the canonical PURL ID belongs to the project's own
// record whichever order normalization visits the records in: an external
// record that got there first moves to its occurrence ID, and edges recorded
// against it follow.
func TestNormalizationReservesCanonicalIDForProjectRecords(t *testing.T) {
	const purl = "pkg:npm/helper@1.0.0"

	// IDs chosen so the external record sorts first and takes the canonical
	// slot before the member arrives.
	orderings := [][2]string{{"a-external", "z-member"}, {"z-external", "a-member"}}
	for _, ids := range orderings {
		externalID, memberID := ids[0], ids[1]
		t.Run(externalID+"/"+memberID, func(t *testing.T) {
			g := sdk.New()
			external := sdk.NewDependencyWithID(externalID, sdk.Dependency{Coordinates: sdk.Coordinates{
				Name: "helper", Version: "1.0.0", Ecosystem: sdk.EcosystemNPM, PURL: purl}})
			external.ResolvedURL = "https://registry.npmjs.org/helper/-/helper-1.0.0.tgz"
			external.Origin = sdk.ArtifactOrigin(external.ResolvedURL)
			member := sdk.NewDependencyWithID(memberID, sdk.Dependency{Coordinates: sdk.Coordinates{
				Name: "helper", Version: "1.0.0", Ecosystem: sdk.EcosystemNPM, PURL: purl, FirstParty: true}})
			parent := sdk.NewDependencyWithID("consumer@1.0.0", sdk.Dependency{Coordinates: sdk.Coordinates{
				Name: "consumer", Version: "1.0.0", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/consumer@1.0.0"}})
			for _, dep := range []*sdk.Dependency{external, member, parent} {
				if err := g.AddNode(dep); err != nil {
					t.Fatal(err)
				}
			}
			if err := g.AddEdge(parent.ID, external.ID); err != nil {
				t.Fatal(err)
			}

			normalizedGraph, err := normalizeGraphPackageIdentity(g)
			if err != nil {
				t.Fatalf("normalizeGraphPackageIdentity() error = %v", err)
			}

			canonical, ok := normalizedGraph.Node(purl)
			if !ok {
				t.Fatalf("no node holds the canonical ID %q", purl)
			}
			if !canonical.FirstParty {
				t.Fatalf("canonical ID held by a non-project record (origin %+v)", originOf(canonical))
			}
			if origin := originOf(canonical); origin != (sdk.DependencyOrigin{}) {
				t.Fatalf("the project's record acquired an origin: %+v", origin)
			}

			// The external occurrence survives elsewhere, with the consumer's
			// edge following it.
			var externalNode *sdk.Dependency
			normalizedGraph.WalkNodes(func(dep *sdk.Dependency) bool {
				if dep.Name == "helper" && !dep.FirstParty {
					externalNode = dep
				}
				return true
			})
			if externalNode == nil {
				t.Fatal("the external occurrence was lost")
			}
			deps, err := normalizedGraph.DirectDependencies("pkg:npm/consumer@1.0.0")
			if err != nil || len(deps) != 1 || deps[0].ID != externalNode.ID {
				t.Fatalf("consumer edge = %v (err %v), want it to follow the external occurrence %q", deps, err, externalNode.ID)
			}
		})
	}
}

// A project-owned record never folds with an external one, even when both
// assert the identical resolution -- project-ownedness is part of resolution
// identity, because the project record resolves from the local source tree
// whatever origin metadata a producer stapled onto it. Otherwise the external
// record could survive the fold holding the canonical ID, and export would
// publish the origin the project-owned component suppresses.
func TestProjectRecordsNeverFoldWithMatchingExternalResolutions(t *testing.T) {
	const (
		purl   = "pkg:npm/helper@1.0.0"
		origin = "https://registry.npmjs.org/helper/-/helper-1.0.0.tgz"
	)

	newRecord := func(t *testing.T, id string, firstParty bool) *sdk.Dependency {
		t.Helper()
		dep := sdk.NewDependencyWithID(id, sdk.Dependency{Coordinates: sdk.Coordinates{
			Name: "helper", Version: "1.0.0", Ecosystem: sdk.EcosystemNPM, PURL: purl, FirstParty: firstParty}})
		dep.Origin = sdk.ArtifactOrigin(origin)
		return dep
	}
	requireSplit := func(t *testing.T, g *sdk.Graph) {
		t.Helper()
		var project, external *sdk.Dependency
		var nodes int
		g.WalkNodes(func(dep *sdk.Dependency) bool {
			if dep.Name != "helper" {
				return true
			}
			nodes++
			if dep.FirstParty {
				project = dep
			} else {
				external = dep
			}
			return true
		})
		if nodes != 2 || project == nil || external == nil {
			t.Fatalf("helper nodes = %d (project %v, external %v), want the project and external records distinct", nodes, project != nil, external != nil)
		}
		if project.ID != purl {
			t.Fatalf("project record ID = %q, want the canonical %q", project.ID, purl)
		}
		if got := originOf(external); got.ArtifactURL != origin {
			t.Fatalf("external origin = %+v, want %q", got, origin)
		}
	}

	// Within one entry, in both visit orders.
	orderings := [][2]string{{"a-external", "z-member"}, {"z-external", "a-member"}}
	for _, ids := range orderings {
		t.Run("within entry "+ids[0], func(t *testing.T) {
			g := sdk.New()
			for _, dep := range []*sdk.Dependency{newRecord(t, ids[0], false), newRecord(t, ids[1], true)} {
				if err := g.AddNode(dep); err != nil {
					t.Fatal(err)
				}
			}
			normalizedGraph, err := normalizeGraphPackageIdentity(g)
			if err != nil {
				t.Fatalf("normalizeGraphPackageIdentity() error = %v", err)
			}
			requireSplit(t, normalizedGraph)
		})
	}

	// Across two manifests, where the scan-wide split decides.
	t.Run("across manifests", func(t *testing.T) {
		buildEntry := func(t *testing.T, relativePath, manifest string, firstParty bool) sdk.DetectionResult {
			t.Helper()
			g := sdk.New()
			if err := g.AddNode(newRecord(t, "helper@1.0.0", firstParty)); err != nil {
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
		consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
			buildEntry(t, "apps/consumer", "apps/consumer/package-lock.json", false),
			buildEntry(t, "packages/helper", "packages/helper/package-lock.json", true),
		})
		if err != nil {
			t.Fatalf("ConsolidateGraphs() error = %v", err)
		}
		merged, err := consolidated.Graphs.ConsolidatedGraph()
		if err != nil {
			t.Fatalf("ConsolidatedGraph() error = %v", err)
		}
		requireSplit(t, merged)
	})
}

// One manifest can also record a package twice -- a Bun lockfile listing one
// name and version from two mirrors, under distinct per-entry IDs. Identity
// normalization rewrites IDs to the canonical PURL; contradicting occurrences
// must survive that collapse as distinct nodes, and agreeing ones must fold.
func TestConsolidateGraphsPreservesOccurrencesWithinOneManifest(t *testing.T) {
	const (
		public  = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		private = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	cases := []struct {
		name      string
		records   []string
		wantNodes int
	}{
		{name: "entries agree", records: []string{public, public}, wantNodes: 1},
		{name: "entries contradict", records: []string{public, private}, wantNodes: 2},
		// A third record repeating an origin folds into its occurrence:
		// A, B, B is two occurrences, not three.
		{name: "a repeated contradiction folds", records: []string{public, private, private}, wantNodes: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := sdk.New()
			for i, artifactURL := range tc.records {
				pkg := sdk.NewDependencyWithID(
					fmt.Sprintf("bun-package:lodash#%d", i),
					sdk.Dependency{Coordinates: sdk.Coordinates{
						Name: "lodash", Version: "4.17.21", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lodash@4.17.21"}},
				)
				pkg.Origin = sdk.ArtifactOrigin(artifactURL)
				if err := g.AddNode(pkg); err != nil {
					t.Fatal(err)
				}
			}

			consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{{
				SubprojectInfo: sdk.Subproject{
					ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
					RelativePath:            ".",
					PrimaryDetector:         "bun-detector",
					DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerBun},
					Ecosystem:               sdk.EcosystemNPM,
				},
				DetectorName: "bun-detector",
				Graphs:       sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "bun.lock", Kind: "bun.lock"}),
			}})
			if err != nil {
				t.Fatalf("ConsolidateGraphs() error = %v", err)
			}
			merged, err := consolidated.Graphs.ConsolidatedGraph()
			if err != nil {
				t.Fatalf("ConsolidatedGraph() error = %v", err)
			}

			var nodes int
			origins := map[string]int{}
			merged.WalkNodes(func(dep *sdk.Dependency) bool {
				if dep.Name != "lodash" {
					return true
				}
				nodes++
				if origin := originOf(dep); origin.ArtifactURL != "" {
					origins[origin.ArtifactURL]++
				}
				return true
			})
			if nodes != tc.wantNodes {
				t.Fatalf("lodash nodes = %d (origins %v), want %d", nodes, origins, tc.wantNodes)
			}
			if tc.wantNodes == 2 && (origins[public] != 1 || origins[private] != 1) {
				t.Fatalf("origins = %v, want both occurrences with their own origins", origins)
			}
		})
	}
}

// When two records witness one resolution, the fold must keep both witnesses'
// usage facts: scopes, locations, and relationship aggregate onto the
// surviving occurrence instead of vanishing with whichever record lost the
// walk order. Exercised through the within-entry occurrence collision (A, B,
// B), where both B clones derive the same occurrence ID.
func TestConsolidateGraphsFoldedWitnessesKeepUsageFacts(t *testing.T) {
	const (
		public  = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		private = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	type record struct {
		url      string
		scope    sdk.Scope
		location string
	}
	witnessRuntime := record{url: private, scope: sdk.ScopeRuntime, location: "packages/app/bun.lock"}
	witnessDev := record{url: private, scope: sdk.ScopeDevelopment, location: "packages/tools/bun.lock"}
	other := record{url: public, scope: sdk.ScopeRuntime, location: "bun.lock"}

	orderings := map[string][]record{
		"runtime witness first": {other, witnessRuntime, witnessDev},
		"dev witness first":     {other, witnessDev, witnessRuntime},
		"witnesses surround":    {witnessRuntime, other, witnessDev},
	}
	for name, records := range orderings {
		t.Run(name, func(t *testing.T) {
			g := sdk.New()
			for i, rec := range records {
				pkg := sdk.NewDependencyWithID(
					fmt.Sprintf("bun-package:lodash#%d", i),
					sdk.Dependency{Coordinates: sdk.Coordinates{
						Name: "lodash", Version: "4.17.21", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lodash@4.17.21"}},
				)
				pkg.Origin = sdk.ArtifactOrigin(rec.url)
				pkg.AddScope(rec.scope)
				pkg.Locations = []sdk.PackageLocation{{RealPath: rec.location}}
				if err := g.AddNode(pkg); err != nil {
					t.Fatal(err)
				}
			}

			consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{{
				SubprojectInfo: sdk.Subproject{
					ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
					RelativePath:            ".",
					PrimaryDetector:         "bun-detector",
					DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerBun},
					Ecosystem:               sdk.EcosystemNPM,
				},
				DetectorName: "bun-detector",
				Graphs:       sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "bun.lock", Kind: "bun.lock"}),
			}})
			if err != nil {
				t.Fatalf("ConsolidateGraphs() error = %v", err)
			}
			merged, err := consolidated.Graphs.ConsolidatedGraph()
			if err != nil {
				t.Fatalf("ConsolidatedGraph() error = %v", err)
			}

			var folded *sdk.Dependency
			merged.WalkNodes(func(dep *sdk.Dependency) bool {
				if dep.Name == "lodash" && originOf(dep).ArtifactURL == private {
					folded = dep
				}
				return true
			})
			if folded == nil {
				t.Fatal("no surviving occurrence for the folded witnesses")
			}

			scopes := map[sdk.Scope]bool{}
			for _, scope := range folded.Scopes {
				scopes[scope] = true
			}
			if !scopes[sdk.ScopeRuntime] || !scopes[sdk.ScopeDevelopment] {
				t.Fatalf("scopes = %v, want both witnesses' scopes", folded.Scopes)
			}
			locations := map[string]bool{}
			for _, location := range folded.Locations {
				locations[location.RealPath] = true
			}
			if !locations[witnessRuntime.location] || !locations[witnessDev.location] {
				t.Fatalf("locations = %v, want both witnesses' locations", folded.Locations)
			}
			if locations[other.location] {
				t.Fatalf("locations = %v: the other occurrence's location leaked into the fold", folded.Locations)
			}
		})
	}
}
