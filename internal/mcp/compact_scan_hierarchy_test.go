package mcp_test

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/mcp"
	"github.com/bomly-dev/bomly-cli/internal/output"
)

func TestBuildCompactScanCountsSubprojectsAndModules(t *testing.T) {
	run := mcp.ScanRunResult{
		Response: output.ScanResponse{
			Command: "scan",
			Manifests: []output.ScanManifest{
				{Path: "package-lock.json", Subproject: "."},
				{Path: "apps/web/package.json", Subproject: "."},
				{Path: "services/api/pom.xml", Subproject: "services/api"},
				{Path: "services/api/module-a/pom.xml", Subproject: "services/api"},
			},
		},
	}
	resp := mcp.BuildCompactScan(run)
	if resp.Summary.Subprojects != 1 {
		t.Fatalf("Subprojects = %d, want 1", resp.Summary.Subprojects)
	}
	if resp.Summary.Modules != 2 {
		t.Fatalf("Modules = %d, want 2", resp.Summary.Modules)
	}
	if resp.Summary.Manifests != 4 {
		t.Fatalf("Manifests = %d, want 4", resp.Summary.Manifests)
	}
}

func TestBuildCompactScanFlatScanOmitsGroupCounts(t *testing.T) {
	run := mcp.ScanRunResult{
		Response: output.ScanResponse{
			Command:   "scan",
			Manifests: []output.ScanManifest{{Path: "go.mod", Subproject: "."}},
		},
	}
	resp := mcp.BuildCompactScan(run)
	if resp.Summary.Subprojects != 0 || resp.Summary.Modules != 0 {
		t.Fatalf("expected zero group counts for flat scan, got %+v", resp.Summary)
	}
}

func TestBuildCompactScanTotalPackagesDedupsAcrossModuleManifests(t *testing.T) {
	shared := output.ScanDependency{ID: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21"}
	run := mcp.ScanRunResult{
		Response: output.ScanResponse{
			Command: "scan",
			Manifests: []output.ScanManifest{
				{Path: "apps/web/package.json", Subproject: ".", Dependencies: []output.ScanDependency{shared}},
				{Path: "packages/lib/package.json", Subproject: ".", Dependencies: []output.ScanDependency{shared}},
			},
		},
	}
	resp := mcp.BuildCompactScan(run)
	if resp.Summary.TotalPackages != 1 {
		t.Fatalf("TotalPackages = %d, want 1 (shared dep must dedup)", resp.Summary.TotalPackages)
	}
}
