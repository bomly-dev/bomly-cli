package cli

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestRenderScanReportIncludesProfessionalSections(t *testing.T) {
	g, registry := newScanTestGraph(t)
	findings := []sdk.Finding{{
		ID:         "OSV-123",
		Kind:       sdk.FindingKindVulnerability,
		Severity:   "high",
		PackageRef: "pkg:npm/react@18.2.0",
		Title:      "Prototype pollution in react",
		Source:     "osv",
	}}
	manifests := []output.ScanManifest{{
		Path:           "package-lock.json",
		Kind:           "package-lock.json",
		Subproject:     ".",
		PackageManager: "npm",
		Packages:       output.PackagesFromGraph(g, registry),
	}}

	report := render.Scan(manifests, g, registry, findings, true, true, false)
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
	g, registry := newScanTestGraph(t)
	report := render.Scan([]output.ScanManifest{{
		Path:           "package-lock.json",
		Kind:           "package-lock.json",
		Subproject:     ".",
		PackageManager: "npm",
		Packages:       output.PackagesFromGraph(g, registry),
	}}, g, registry, nil, false, false, false)
	if !strings.Contains(report, "Policy evaluation not enabled") {
		t.Fatalf("expected not-audited message, got:\n%s", report)
	}
	if strings.Contains(report, "â€”") || strings.Contains(report, "Ã¢â‚¬â€") {
		t.Fatalf("expected mojibake to be removed, got:\n%s", report)
	}
}

// newScanTestGraph returns a small npm-shaped graph and a matching package
// registry. Detection-time license + scope facts live on the dependencies;
// matching-stage licenses live on the registry packages keyed by PURL.
func newScanTestGraph(t *testing.T) (*sdk.Graph, *sdk.PackageRegistry) {
	t.Helper()
	g := sdk.New()
	registry := sdk.NewPackageRegistry()

	type fixture struct {
		id, name, version, purl string
		scope                   sdk.Scope
		license                 string
	}
	for _, f := range []fixture{
		{id: "app@1.0.0", name: "app", version: "1.0.0", purl: "pkg:npm/app@1.0.0", scope: sdk.ScopeRuntime, license: "MIT"},
		{id: "react@18.2.0", name: "react", version: "18.2.0", purl: "pkg:npm/react@18.2.0", scope: sdk.ScopeRuntime, license: "MIT"},
		{id: "zod@3.23.0", name: "zod", version: "3.23.0", purl: "pkg:npm/zod@3.23.0", scope: sdk.ScopeDevelopment, license: "Apache-2.0"},
		{id: "loose-envify@1.4.0", name: "loose-envify", version: "1.4.0", purl: "pkg:npm/loose-envify@1.4.0", scope: sdk.ScopeRuntime},
	} {
		dep := sdk.NewDependencyWithID(f.id, sdk.Dependency{
			Name:    f.name,
			Version: f.version,
			PURL:    f.purl,
			Scopes:  sdk.ScopesOf(f.scope),
		})
		if f.license != "" {
			sdk.SetDetectionLicenses(dep, []sdk.PackageLicense{{SPDXExpression: f.license}})
		}
		if err := g.AddNode(dep); err != nil {
			t.Fatalf("add package %s: %v", f.id, err)
		}
		regPkg := registry.Ensure(f.purl)
		regPkg.Name = f.name
		regPkg.Version = f.version
		if f.license != "" {
			regPkg.Licenses = []sdk.PackageLicense{{SPDXExpression: f.license}}
		}
	}
	for _, edge := range [][2]string{
		{"app@1.0.0", "react@18.2.0"},
		{"app@1.0.0", "zod@3.23.0"},
		{"react@18.2.0", "loose-envify@1.4.0"},
	} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add dependency %v: %v", edge, err)
		}
	}
	return g, registry
}
