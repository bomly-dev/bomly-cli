package cli

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestRenderScanReportShowsPackageCountAndDirectDeps(t *testing.T) {
	g, registry := newScanTestGraph(t)
	findings := []sdk.Finding{{
		ID:         "OSV-123",
		Kind:       sdk.FindingKindVulnerability,
		Severity:   "high",
		PackageRef: "pkg:npm/react@18.2.0",
		Title:      "Prototype pollution in react",
		Source:     "osv",
	}}

	report := render.Scan(g, registry, findings, nil, true, true, false, nil, "", nil)

	for _, want := range []string{
		"packages",
		"direct",
		"transitive",
		"scopes:",
		"Top-level dependencies",
		"react",
		"Findings",
		"OSV-123",
		"HIGH",
	} {
		if !strings.Contains(render.StripANSI(report), want) {
			t.Fatalf("expected report to contain %q, got:\n%s", want, report)
		}
	}
}

func TestRenderScanReportWithEnrichmentShowsEnrichmentLine(t *testing.T) {
	g, registry := newScanTestGraph(t)
	stats := []sdk.MatcherStats{
		{Name: "osv", DisplayName: "OSV"},
		{Name: "deps.dev", DisplayName: "deps.dev"},
	}
	report := render.Scan(g, registry, nil, stats, true, false, false, nil, "", nil)
	stripped := render.StripANSI(report)
	if !strings.Contains(stripped, "Enriched via OSV") {
		t.Fatalf("expected enrichment line, got:\n%s", report)
	}
}

func TestRenderScanReportWithoutEnrichmentSkipsEnrichmentLine(t *testing.T) {
	g, registry := newScanTestGraph(t)
	report := render.Scan(g, registry, nil, nil, false, false, false, nil, "", nil)
	stripped := render.StripANSI(report)
	if strings.Contains(stripped, "Enriched via") {
		t.Fatalf("unexpected enrichment line when not enriched, got:\n%s", report)
	}
	if strings.Contains(stripped, "Findings") {
		t.Fatalf("unexpected findings section when no findings, got:\n%s", report)
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
		dep := sdk.NewDependencyWithID(f.id, sdk.Dependency{Coordinates: sdk.Coordinates{Name: f.name,
			Version: f.version,
			PURL:    f.purl}, Scopes: sdk.ScopesOf(f.scope),
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
