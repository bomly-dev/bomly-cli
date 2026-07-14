package cli

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
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

	report := render.Scan(g, registry, findings, nil, true, true, false, nil, nil, nil)

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
	report := render.Scan(g, registry, nil, stats, true, false, false, nil, nil, nil)
	stripped := render.StripANSI(report)
	if !strings.Contains(stripped, "Enriched via OSV") {
		t.Fatalf("expected enrichment line, got:\n%s", report)
	}
}

func TestRenderScanReportWithoutEnrichmentSkipsEnrichmentLine(t *testing.T) {
	g, registry := newScanTestGraph(t)
	report := render.Scan(g, registry, nil, nil, false, false, false, nil, nil, nil)
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

func TestRenderScanReportGroupsManifestsBySubprojectAndModule(t *testing.T) {
	g, registry := newScanTestGraph(t)
	manifests := []output.ScanManifest{
		{Path: "package-lock.json", Subproject: ".", PackageManager: sdk.PackageManagerNPM, Dependencies: make([]output.ScanDependency, 3)},
		{Path: "apps/web/package.json", Subproject: ".", PackageManager: sdk.PackageManagerNPM, Dependencies: make([]output.ScanDependency, 2)},
		{Path: "services/api/pom.xml", Subproject: "services/api", PackageManager: sdk.PackageManagerMaven, Dependencies: make([]output.ScanDependency, 1)},
		{Path: "services/api/module-a/pom.xml", Subproject: "services/api", PackageManager: sdk.PackageManagerMaven, Dependencies: make([]output.ScanDependency, 4)},
	}
	report := render.StripANSI(render.Scan(g, registry, nil, nil, false, false, false, nil, manifests, nil))

	for _, want := range []string{
		"in 4 manifests",
		"package-lock.json — 3 packages",
		"apps/web (module, npm) — 2 packages",
		"services/api (subproject, maven)",
		"pom.xml — 1 packages",
		"module-a (module, maven) — 4 packages",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected grouped manifest tree to contain %q, got:\n%s", want, report)
		}
	}
}

func TestRenderScanReportFlatScanHasNoManifestTree(t *testing.T) {
	g, registry := newScanTestGraph(t)
	manifests := []output.ScanManifest{
		{Path: "package-lock.json", Subproject: ".", PackageManager: sdk.PackageManagerNPM},
	}
	report := render.StripANSI(render.Scan(g, registry, nil, nil, false, false, false, nil, manifests, nil))
	if !strings.Contains(report, "in 1 manifest") {
		t.Fatalf("expected manifest count from manifests slice, got:\n%s", report)
	}
	if strings.Contains(report, "└─ package-lock.json") || strings.Contains(report, "(subproject") {
		t.Fatalf("flat scan must not render a manifest tree, got:\n%s", report)
	}
}

func TestRenderScanReportMergedNodeUsesPackageName(t *testing.T) {
	g, registry := newScanTestGraph(t)
	manifests := []output.ScanManifest{
		{Path: "package-lock.json", Subproject: ".", PackageManager: sdk.PackageManagerNPM, Dependencies: []output.ScanDependency{
			{ID: "root@1.0.0", Name: "demo-workspace", DependsOn: []string{"ms@2.1.3"}},
			{ID: "ms@2.1.3", Name: "ms"},
		}},
		{Path: "apps/web/package.json", Subproject: ".", PackageManager: sdk.PackageManagerNPM, Dependencies: []output.ScanDependency{
			{ID: "web@1.0.0", Name: "web", DependsOn: []string{"minimist@1.2.5"}},
			{ID: "minimist@1.2.5", Name: "minimist"},
		}},
	}
	report := render.StripANSI(render.Scan(g, registry, nil, nil, false, false, false, nil, manifests, nil))
	if !strings.Contains(report, "web (module, npm) — 2 packages [apps/web/package.json]") {
		t.Fatalf("expected merged module line named by package with manifest hint, got:\n%s", report)
	}
}

func TestRenderScanReportTopLevelDepsCoverAllModules(t *testing.T) {
	g := sdk.New()
	parent := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "parent", Version: "1.0.0", Type: sdk.PackageTypeApplication}})
	web := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "web", Version: "1.0.0", Type: sdk.PackageTypeApplication}})
	core := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "core", Version: "1.0.0", Type: sdk.PackageTypeApplication}})
	coreDep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "commons-lang3", Version: "3.12.0"}, Scopes: sdk.ScopesOf(sdk.ScopeRuntime)})
	webDep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "jackson-databind", Version: "2.13.0"}, Scopes: sdk.ScopesOf(sdk.ScopeRuntime)})
	for _, pkg := range []*sdk.Dependency{parent, web, core, coreDep, webDep} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add node: %v", err)
		}
	}
	// web -> core makes core a non-root module; its direct dep must still be
	// listed as top-level.
	for _, edge := range [][2]string{{web.ID, core.ID}, {web.ID, webDep.ID}, {core.ID, coreDep.ID}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge: %v", err)
		}
	}
	report := render.StripANSI(render.Scan(g, sdk.NewPackageRegistry(), nil, nil, false, false, false, nil, nil, nil))
	for _, want := range []string{"commons-lang3", "jackson-databind"} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected %q in top-level dependencies, got:\n%s", want, report)
		}
	}
}
