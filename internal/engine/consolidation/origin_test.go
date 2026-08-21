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
		second    string
		wantNodes int
	}{
		{name: "entries agree", second: public, wantNodes: 1},
		{name: "entries contradict", second: private, wantNodes: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := sdk.New()
			for i, artifactURL := range []string{public, tc.second} {
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
