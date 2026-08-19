package consolidation

import (
	"fmt"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

// originOf returns the origin a node publishes, or the zero value when it has
// none, so cases can compare plain structs.
func originOf(dep *sdk.Dependency) sdk.PackageOrigin {
	if dep == nil {
		return sdk.PackageOrigin{}
	}
	if origin := dep.Origin.Normalized(); origin != nil {
		return *origin
	}
	return sdk.PackageOrigin{}
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
// arrives as two nodes. Merging keeps one and drops the other, so the
// disagreement has to be settled while both are still visible.
func TestConsolidateGraphsSettlesOriginAcrossManifests(t *testing.T) {
	const (
		public  = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		private = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	cases := []struct {
		name  string
		left  string
		right string
		want  sdk.PackageOrigin
	}{
		{
			name:  "subprojects agree",
			left:  public,
			right: public,
			want:  sdk.PackageOrigin{ArtifactURL: public},
		},
		{
			name:  "one subproject resolved a private mirror",
			left:  public,
			right: private,
		},
		{
			name:  "one subproject recorded nothing",
			left:  public,
			right: "",
			want:  sdk.PackageOrigin{ArtifactURL: public},
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
			var node *sdk.Dependency
			merged.WalkNodes(func(dep *sdk.Dependency) bool {
				if dep.Name == "lodash" {
					node = dep
				}
				return true
			})
			if node == nil {
				t.Fatalf("expected lodash in the merged graph; ids present: %v", graphIDs(merged))
			}
			if got := originOf(node); got != tc.want {
				t.Fatalf("merged origin = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// One manifest can record a package twice with different locations -- a Bun
// lockfile listing one name and version from two mirrors. Both nodes normalize
// to one canonical identity and only one survives, so the disagreement has to
// be settled while both are still there. This is the single-manifest case,
// which never reaches cross-entry reconciliation.
func TestConsolidateGraphsSettlesOriginWithinOneManifest(t *testing.T) {
	const (
		public  = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		private = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	cases := []struct {
		name  string
		left  string
		right string
		want  sdk.PackageOrigin
	}{
		{name: "entries agree", left: public, right: public, want: sdk.PackageOrigin{ArtifactURL: public}},
		{name: "entries disagree", left: public, right: private},
		{name: "one entry says nothing", left: public, right: "", want: sdk.PackageOrigin{ArtifactURL: public}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Distinct node IDs, one canonical PURL: what a lockfile parser
			// produces when it disambiguates a duplicate package key.
			g := sdk.New()
			for i, artifactURL := range []string{tc.left, tc.right} {
				pkg := sdk.NewDependencyWithID(
					fmt.Sprintf("bun-package:lodash@4.17.21#%d", i),
					sdk.Dependency{Coordinates: sdk.Coordinates{
						Name: "lodash", Version: "4.17.21", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lodash@4.17.21"}},
				)
				if artifactURL != "" {
					pkg.Origin = sdk.ArtifactOrigin(artifactURL)
				}
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
			var checked int
			merged.WalkNodes(func(dep *sdk.Dependency) bool {
				if dep.Name != "lodash" {
					return true
				}
				checked++
				if got := originOf(dep); got != tc.want {
					t.Fatalf("origin = %+v, want %+v", got, tc.want)
				}
				return true
			})
			if checked != 1 {
				t.Fatalf("found %d lodash nodes, want 1", checked)
			}
		})
	}
}
