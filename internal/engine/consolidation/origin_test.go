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
