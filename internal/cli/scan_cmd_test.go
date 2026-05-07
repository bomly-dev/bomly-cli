package cli

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestRenderScanReportIncludesProfessionalSections(t *testing.T) {
	g := newScanTestGraph(t)
	findings := []sdk.Finding{{
		ID:       "OSV-123",
		Kind:     sdk.FindingKindVulnerability,
		Severity: "high",
		Package:  sdk.NewPackageRef("react", "18.2.0"),
		Title:    "Prototype pollution in react",
		Source:   "osv",
	}}
	manifests := []output.ScanManifest{{
		Path:           "package-lock.json",
		Kind:           "package-lock.json",
		Subproject:     ".",
		PackageManager: "npm",
		Packages:       output.PackagesFromGraph(g),
	}}

	report := render.Scan(manifests, g, findings, true, true)
	for _, want := range []string{
		"Executive Summary",
		"Manifests",
		"package-lock.json",
		"Dependency Inventory",
		"Policy Findings",
		"License Overview",
		"LICENSES",
		"IDENTIFIER",
		"react",
		"loose-envify",
		"1 total (1 high)",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected report to contain %q, got:\n%s", want, report)
		}
	}
	if strings.Contains(report, "-> [") {
		t.Fatalf("expected report output instead of tree output, got:\n%s", report)
	}
}

func TestRenderScanReportWithoutFindingsUsesCleanMessage(t *testing.T) {
	g := newScanTestGraph(t)
	report := render.Scan([]output.ScanManifest{{
		Path:           "package-lock.json",
		Kind:           "package-lock.json",
		Subproject:     ".",
		PackageManager: "npm",
		Packages:       output.PackagesFromGraph(g),
	}}, g, nil, false, false)
	if !strings.Contains(report, "Policy evaluation not enabled") {
		t.Fatalf("expected not-audited message, got:\n%s", report)
	}
	if strings.Contains(report, "â€”") || strings.Contains(report, "Ã¢â‚¬â€") {
		t.Fatalf("expected mojibake to be removed, got:\n%s", report)
	}
}

func newScanTestGraph(t *testing.T) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	for _, pkg := range []*sdk.Package{
		{ID: "app@1.0.0", Name: "app", Version: "1.0.0", Scope: string(sdk.ScopeRuntime), Licenses: []sdk.PackageLicense{{Value: "MIT"}}},
		{ID: "react@18.2.0", Name: "react", Version: "18.2.0", Scope: string(sdk.ScopeRuntime), Licenses: []sdk.PackageLicense{{SPDXExpression: "MIT"}}},
		{ID: "zod@3.23.0", Name: "zod", Version: "3.23.0", Scope: string(sdk.ScopeDevelopment), Licenses: []sdk.PackageLicense{{SPDXExpression: "Apache-2.0"}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Scope: string(sdk.ScopeRuntime)},
	} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package %s: %v", pkg.ID, err)
		}
	}
	for _, edge := range [][2]string{
		{"app@1.0.0", "react@18.2.0"},
		{"app@1.0.0", "zod@3.23.0"},
		{"react@18.2.0", "loose-envify@1.4.0"},
	} {
		if err := g.AddDependency(edge[0], edge[1]); err != nil {
			t.Fatalf("add dependency %v: %v", edge, err)
		}
	}
	return g
}
