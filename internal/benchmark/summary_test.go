package benchmark

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestBuildSourceSummaryScoresPackagesAndRelationships(t *testing.T) {
	bomly := &sbom.Document{
		Tools: []string{"bomly-cli", "bomly-detector:npm-detector"},
		Components: []sbom.Component{
			{ID: "app", PURL: "pkg:npm/app@1.0.0", Scope: "runtime"},
			{ID: "exact", PURL: "pkg:npm/exact@1.0.0"},
			{ID: "version", PURL: "pkg:npm/version@2.0.0"},
			{ID: "extra", PURL: "pkg:npm/extra@1.0.0"},
			{ID: "ignored", Name: "without-purl"},
		},
		Dependencies: []sbom.Dependency{{Ref: "app", DependsOn: []string{"exact", "extra"}}},
	}
	source := &sbom.Document{
		Components: []sbom.Component{
			{ID: "app", PURL: "pkg:npm/app@1.0.0"},
			{ID: "exact", PURL: "pkg:npm/exact@1.0.0"},
			{ID: "version", PURL: "pkg:npm/version@1.0.0"},
			{ID: "missing", PURL: "pkg:npm/missing@1.0.0"},
			{ID: "ignored", Name: "without-purl"},
		},
		Dependencies: []sbom.Dependency{{Ref: "app", DependsOn: []string{"exact", "missing"}}},
	}

	summary := BuildSourceSummary("github", bomly, source, SourceArtifacts{})
	if summary.Packages.ExactMatches != 2 || summary.Packages.VersionMismatch != 1 ||
		summary.Packages.BomlyOnly != 1 || summary.Packages.SourceOnly != 1 {
		t.Fatalf("unexpected package metrics: %#v", summary.Packages)
	}
	if summary.Packages.Score != 62.5 {
		t.Fatalf("package score = %v, want 62.5", summary.Packages.Score)
	}
	if summary.Packages.BomlyIgnored != 1 || summary.Packages.SourceIgnored != 1 {
		t.Fatalf("ignored packages = %#v", summary.Packages)
	}
	if summary.Relationships.Matched != 1 || summary.Relationships.BomlyOnly != 1 || summary.Relationships.SourceOnly != 1 {
		t.Fatalf("unexpected relationship metrics: %#v", summary.Relationships)
	}
	if summary.Relationships.Score == nil || *summary.Relationships.Score != 50 {
		t.Fatalf("relationship score = %#v, want 50", summary.Relationships.Score)
	}
	if summary.Scores.Overall != 56.25 {
		t.Fatalf("overall score = %v, want 56.25", summary.Scores.Overall)
	}
	if !reflect.DeepEqual(summary.Detectors, []string{"npm-detector"}) {
		t.Fatalf("detectors = %#v", summary.Detectors)
	}
}

func TestRenderTextShowsUnavailableEdgesAndIgnoredPackages(t *testing.T) {
	packageScore := 100.0
	summary := RunSummary{
		Status: "completed",
		RunDir: ".benchmark-runs/latest",
		Cases: []CaseSummary{{
			Case:      "scan-npm",
			Ecosystem: sdk.EcosystemNPM,
			Sources: []SourceSummary{{
				Source:   "github",
				Status:   "completed",
				Packages: &PackageMetrics{BomlyIgnored: 2, SourceIgnored: 1},
				Scores:   &ScoreSummary{Package: packageScore, Overall: packageScore},
			}},
		}},
		Scores: &ScoreSummary{Package: packageScore, Overall: packageScore},
	}
	var out bytes.Buffer
	if err := RenderText(&out, summary); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"IGNORED(B/S)", "N/A", "2/1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestBuildSourceSummaryUsesPackageScoreWhenEdgesAreUnavailable(t *testing.T) {
	doc := &sbom.Document{Components: []sbom.Component{{ID: "a", PURL: "pkg:npm/a@1.0.0"}}}
	summary := BuildSourceSummary("syft", doc, doc, SourceArtifacts{})
	if summary.Relationships.Score != nil {
		t.Fatalf("relationship score = %#v, want nil", summary.Relationships.Score)
	}
	if summary.Scores.Overall != 100 {
		t.Fatalf("overall score = %v, want 100", summary.Scores.Overall)
	}
}

func TestFilterDocumentKeepsOnlySelectedEcosystemAndInternalEdges(t *testing.T) {
	doc := &sbom.Document{
		Components: []sbom.Component{
			{ID: "npm-a", PURL: "pkg:npm/a@1.0.0"},
			{ID: "npm-b", PURL: "pkg:npm/b@1.0.0"},
			{ID: "go-c", PURL: "pkg:golang/example.com/c@v1.0.0"},
		},
		Dependencies: []sbom.Dependency{
			{Ref: "npm-a", DependsOn: []string{"npm-b", "go-c"}},
			{Ref: "go-c", DependsOn: []string{"npm-b"}},
		},
	}

	filtered := FilterDocument(doc, sdk.EcosystemNPM)
	if len(filtered.Components) != 2 {
		t.Fatalf("components = %#v", filtered.Components)
	}
	if len(filtered.Dependencies) != 1 || !reflect.DeepEqual(filtered.Dependencies[0].DependsOn, []string{"npm-b"}) {
		t.Fatalf("dependencies = %#v", filtered.Dependencies)
	}
}
