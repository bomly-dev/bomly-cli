package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestConsolidateGraphs_PreservesOriginAndFallbackProvenance(t *testing.T) {
	graph := model.New()
	root := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: "maven", Org: "org.example", Name: "app", Version: "1.0.0", PURL: "pkg:maven/org.example/app@1.0.0"}})
	if err := graph.AddNode(root); err != nil {
		t.Fatalf("add root: %v", err)
	}

	subproject := plugin.Subproject{
		ExecutionTarget:         plugin.ExecutionTarget{Kind: plugin.ExecutionTargetWorkingDirectory, Location: "/repo"},
		RelativePath:            ".",
		PrimaryDetector:         "maven-detector",
		DetectedPackageManagers: []model.PackageManager{model.PackageManagerMaven},
		Ecosystem:               model.EcosystemMaven,
	}
	consolidated, err := ConsolidateGraphs([]plugin.DetectionResult{{
		SubprojectInfo: subproject,
		DetectorName:   "syft-detector",
		Origin:         plugin.BundledOrigin,
		Technique:      plugin.MultipleTechnique,
		FallbackFrom:   "maven-detector",
		FallbackReason: "not ready: java executable not found on PATH",
		Graphs: model.SingleGraphContainer(graph, model.ManifestMetadata{
			Path: "pom.xml",
			Kind: "pom.xml",
			Resolution: &model.ResolutionMetadata{
				Fallback: &model.ResolutionFallback{From: "maven-detector", Reason: "not ready: java executable not found on PATH"},
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
	if manifest.Origin != plugin.BundledOrigin {
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
