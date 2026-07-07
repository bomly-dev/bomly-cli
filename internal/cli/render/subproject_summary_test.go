package render

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestBuildSubprojectSummary_CountsPerPathPerEcosystem(t *testing.T) {
	// A single path ("." root) hosting two ecosystems must be reported as two
	// discovered subprojects, not collapsed into one.
	manifests := []output.ScanManifest{
		{Subproject: ".", Ecosystem: model.EcosystemGitHub, PackageManager: model.PackageManagerGitHubActions},
		{Subproject: ".", Ecosystem: model.EcosystemNPM, PackageManager: model.PackageManagerNPM},
	}
	got := BuildSubprojectSummary(manifests)
	want := "Discovered 2 subprojects: . (github-actions), . (npm)"
	if got != want {
		t.Fatalf("subproject summary:\n got %q\nwant %q", got, want)
	}
}

func TestBuildSubprojectSummary_DedupesRepeatedPathEcosystem(t *testing.T) {
	// The same (path, ecosystem) appearing across multiple manifests (e.g. one
	// per lockfile) counts once.
	manifests := []output.ScanManifest{
		{Subproject: "web", Ecosystem: model.EcosystemNPM, PackageManager: model.PackageManagerNPM},
		{Subproject: "web", Ecosystem: model.EcosystemNPM, PackageManager: model.PackageManagerNPM},
	}
	got := BuildSubprojectSummary(manifests)
	want := "Discovered 1 subproject: web (npm)"
	if got != want {
		t.Fatalf("subproject summary:\n got %q\nwant %q", got, want)
	}
}

func TestBuildSubprojectSummary_EmptyWhenNoNamedSubprojects(t *testing.T) {
	if got := BuildSubprojectSummary([]output.ScanManifest{{Subproject: ""}}); got != "" {
		t.Fatalf("expected empty summary, got %q", got)
	}
}
