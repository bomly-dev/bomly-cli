package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestConsolidateGraphs_PreservesOriginAndFallbackProvenance(t *testing.T) {
	graph := sdk.New()
	root := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "maven", Org: "org.example", Name: "app", Version: "1.0.0", PURL: "pkg:maven/org.example/app@1.0.0"}})
	if err := graph.AddNode(root); err != nil {
		t.Fatalf("add root: %v", err)
	}

	subproject := sdk.Subproject{
		ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetWorkingDirectory, Location: "/repo"},
		RelativePath:            ".",
		PrimaryDetector:         "maven-detector",
		DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerMaven},
		Ecosystem:               sdk.EcosystemMaven,
	}
	consolidated, err := ConsolidateGraphs([]sdk.DetectionResult{{
		SubprojectInfo: subproject,
		DetectorName:   "syft-detector",
		Origin:         sdk.BundledOrigin,
		Technique:      sdk.MultipleTechnique,
		FallbackFrom:   "maven-detector",
		FallbackReason: "not ready: java executable not found on PATH",
		Graphs: sdk.SingleGraphContainer(graph, sdk.ManifestMetadata{
			Path: "pom.xml",
			Kind: "pom.xml",
			Resolution: &sdk.ResolutionMetadata{
				Fallback: &sdk.ResolutionFallback{From: "maven-detector", Reason: "not ready: java executable not found on PATH"},
			},
		}),
	}})
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	if len(consolidated.Manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(consolidated.Manifests))
	}
	manifest := consolidated.Manifests[0]
	if manifest.Origin != sdk.BundledOrigin {
		t.Fatalf("expected origin to survive consolidation, got %q", manifest.Origin)
	}
	resolution := manifest.Entry.Manifest.Resolution
	if resolution == nil || resolution.Fallback == nil {
		t.Fatalf("expected fallback resolution provenance to survive consolidation, got %#v", resolution)
	}
	if resolution.Fallback.From != "maven-detector" {
		t.Fatalf("unexpected fallback source %q", resolution.Fallback.From)
	}
}
