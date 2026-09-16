package output_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/engine/consolidation"
	"github.com/bomly-dev/bomly-cli/internal/output"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestBuildScanResponseIncludesFallbackProvenance(t *testing.T) {
	g := newViewTestGraph(t)
	results := []plugin.DetectionResult{{
		SubprojectInfo: plugin.Subproject{
			RelativePath:            ".",
			PrimaryDetector:         "maven-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerMaven},
			Ecosystem:               model.EcosystemMaven,
		},
		DetectorName:   "syft-detector",
		FallbackFrom:   "maven-detector",
		FallbackReason: "not ready: java executable not found on PATH",
		Graphs: &model.GraphContainer{Entries: []model.GraphEntry{{
			Graph: g,
			Manifest: model.ManifestMetadata{
				Path: "pom.xml",
				Kind: model.ManifestKindPomXML,
				Resolution: &model.ResolutionMetadata{
					Fallback: &model.ResolutionFallback{From: "maven-detector", Reason: "not ready: java executable not found on PATH"},
				},
			},
		}}},
	}}
	consolidated, err := consolidation.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	response := output.BuildScanResponse(output.ProjectDescriptor{Name: "demo", Path: "/repo"}, consolidated, nil, nil, time.Now().Add(-time.Second))
	if len(response.Manifests) != 1 {
		t.Fatalf("expected one manifest, got %d", len(response.Manifests))
	}
	resolution := response.Manifests[0].Resolution
	if resolution == nil || resolution.Fallback == nil {
		t.Fatalf("expected fallback resolution provenance, got %#v", resolution)
	}
	if resolution.Fallback.From != "maven-detector" || !strings.Contains(resolution.Fallback.Reason, "java executable not found") {
		t.Fatalf("unexpected fallback provenance %#v", resolution.Fallback)
	}

	payload, err := json.Marshal(response.Manifests[0])
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if !strings.Contains(string(payload), `"fallback":{"from":"maven-detector"`) {
		t.Fatalf("expected fallback object in manifest JSON, got %s", payload)
	}
}

func TestBuildScanResponseOmitsFallbackWhenAbsent(t *testing.T) {
	g := newViewTestGraph(t)
	results := []plugin.DetectionResult{{
		SubprojectInfo: plugin.Subproject{
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Graphs: &model.GraphContainer{Entries: []model.GraphEntry{{
			Graph:    g,
			Manifest: model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}}
	consolidated, err := consolidation.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	response := output.BuildScanResponse(output.ProjectDescriptor{Name: "demo", Path: "/repo"}, consolidated, nil, nil, time.Now().Add(-time.Second))
	payload, err := json.Marshal(response.Manifests[0])
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if strings.Contains(string(payload), `"fallback"`) {
		t.Fatalf("expected no fallback key in manifest JSON, got %s", payload)
	}
}
