package output_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/engine/consolidation"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestBuildScanResponseIncludesFallbackProvenance(t *testing.T) {
	g := newViewTestGraph(t)
	results := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			RelativePath:            ".",
			PrimaryDetector:         "maven-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerMaven},
			Ecosystem:               sdk.EcosystemMaven,
		},
		DetectorName:   "syft-detector",
		FallbackFrom:   "maven-detector",
		FallbackReason: "not ready: java executable not found on PATH",
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph: g,
			Manifest: sdk.ManifestMetadata{
				Path: "pom.xml",
				Kind: sdk.ManifestKindPomXML,
				Resolution: &sdk.ResolutionMetadata{
					Fallback: &sdk.ResolutionFallback{From: "maven-detector", Reason: "not ready: java executable not found on PATH"},
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
	results := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    g,
			Manifest: sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
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
