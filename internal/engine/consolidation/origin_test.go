package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

// subprojectResult builds one manifest's detection result carrying a single
// package whose origin the caller chooses.
func subprojectResult(t *testing.T, relativePath, manifest, artifactURL string) sdk.DetectionResult {
	t.Helper()

	g := sdk.New()
	pkg := sdk.NewDependencyWithID("lodash@4.17.21", sdk.Dependency{Coordinates: sdk.Coordinates{
		Name: "lodash", Version: "4.17.21", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lodash@4.17.21"}})
	if artifactURL != "" {
		detectors.SetOriginArtifact(pkg, artifactURL)
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
		want  detectors.Origin
	}{
		{
			name:  "subprojects agree",
			left:  public,
			right: public,
			want:  detectors.Origin{ArtifactURL: public},
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
			want:  detectors.Origin{ArtifactURL: public},
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
			if got := detectors.OriginFrom(node.Metadata); got != tc.want {
				t.Fatalf("merged origin = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The surviving node is whichever the merge happens to keep, so every
// occurrence has to carry the settled answer, not just the first.
func TestConsolidateGraphsSettlesEveryOccurrence(t *testing.T) {
	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{
		subprojectResult(t, "apps/web", "apps/web/package-lock.json", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
		subprojectResult(t, "services/api", "services/api/package-lock.json", "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"),
	})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}

	for _, entry := range consolidated.Graphs.Entries {
		if entry.Graph == nil {
			continue
		}
		entry.Graph.WalkNodes(func(node *sdk.Dependency) bool {
			if got := detectors.OriginFrom(node.Metadata); !got.Empty() {
				t.Errorf("%s still claims %+v after the subprojects disagreed", node.ID, got)
			}
			return true
		})
	}
}
