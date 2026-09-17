package cli

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestRenderScanReportShowsPackageCountAndDirectDeps(t *testing.T) {
	g, registry := newScanTestGraph(t)
	findings := []model.Finding{{
		ID:         "OSV-123",
		Kind:       model.FindingKindVulnerability,
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
		"runtime",
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
	stats := []plugin.MatcherStats{
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
func newScanTestGraph(t *testing.T) (*model.Graph, *model.PackageRegistry) {
	t.Helper()
	g := model.New()
	registry := model.NewPackageRegistry()

	type fixture struct {
		id, name, version, purl string
		scope                   model.Scope
		license                 string
	}
	for _, f := range []fixture{
		{id: "app@1.0.0", name: "app", version: "1.0.0", purl: "pkg:npm/app@1.0.0", scope: model.ScopeRuntime, license: "MIT"},
		{id: "react@18.2.0", name: "react", version: "18.2.0", purl: "pkg:npm/react@18.2.0", scope: model.ScopeRuntime, license: "MIT"},
		{id: "zod@3.23.0", name: "zod", version: "3.23.0", purl: "pkg:npm/zod@3.23.0", scope: model.ScopeDevelopment, license: "Apache-2.0"},
		{id: "loose-envify@1.4.0", name: "loose-envify", version: "1.4.0", purl: "pkg:npm/loose-envify@1.4.0", scope: model.ScopeRuntime},
	} {
		dep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: f.name,
			Version: f.version,
			PURL:    f.purl}, Scopes: model.ScopesOf(f.scope),
		})
		if f.license != "" {
			model.SetDetectionLicenses(dep, []model.PackageLicense{{SPDXExpression: f.license}})
		}
		if err := g.AddNode(dep); err != nil {
			t.Fatalf("add package %s: %v", f.id, err)
		}
		regPkg := registry.Ensure(f.purl)
		regPkg.Name = f.name
		regPkg.Version = f.version
		if f.license != "" {
			regPkg.Licenses = []model.PackageLicense{{SPDXExpression: f.license}}
		}
	}
	for _, edge := range [][2]string{
		{"app@1.0.0", "react@18.2.0"},
		{"app@1.0.0", "zod@3.23.0"},
		{"react@18.2.0", "loose-envify@1.4.0"},
	} {
		if err := g.AddEdge(testnodes.ID(g, edge[0]), testnodes.ID(g, edge[1])); err != nil {
			t.Fatalf("add dependency %v: %v", edge, err)
		}
	}
	return g, registry
}

func TestRenderScanReportGroupsManifestsBySubprojectAndModule(t *testing.T) {
	g, registry := newScanTestGraph(t)
	manifests := []output.ScanManifest{
		{Path: "package-lock.json", Subproject: ".", PackageManager: model.PackageManagerNPM, Dependencies: make([]output.ScanDependency, 3)},
		{Path: "apps/web/package.json", Subproject: ".", PackageManager: model.PackageManagerNPM, Dependencies: make([]output.ScanDependency, 2)},
		{Path: "services/api/pom.xml", Subproject: "services/api", PackageManager: model.PackageManagerMaven, Dependencies: make([]output.ScanDependency, 1)},
		{Path: "services/api/module-a/pom.xml", Subproject: "services/api", PackageManager: model.PackageManagerMaven, Dependencies: make([]output.ScanDependency, 4)},
	}
	report := render.StripANSI(render.Scan(g, registry, nil, nil, false, false, false, nil, manifests, nil))

	for _, want := range []string{
		"in 4 manifests",
		// Modules nest under the manifest that resolves them.
		"package-lock.json — 3 packages, 1 module",
		"│  └─ apps/web (module, npm) — 2 packages [apps/web/package.json]",
		"services/api (subproject, maven)",
		"pom.xml — 1 package, 1 module",
		"└─ module-a (module, maven) — 4 packages [services/api/module-a/pom.xml]",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected grouped manifest tree to contain %q, got:\n%s", want, report)
		}
	}
}

func TestRenderScanReportFlatScanHasNoManifestTree(t *testing.T) {
	g, registry := newScanTestGraph(t)
	manifests := []output.ScanManifest{
		{Path: "package-lock.json", Subproject: ".", PackageManager: model.PackageManagerNPM},
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
		{Path: "package-lock.json", Subproject: ".", PackageManager: model.PackageManagerNPM, Dependencies: []output.ScanDependency{
			{ID: "root@1.0.0", Name: "demo-workspace", DependsOn: []string{"ms@2.1.3"}},
			{ID: "ms@2.1.3", Name: "ms"},
		}},
		{Path: "apps/web/package.json", Subproject: ".", PackageManager: model.PackageManagerNPM, Dependencies: []output.ScanDependency{
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
	g := model.New()
	parent := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "parent", Version: "1.0.0", Type: model.PackageTypeApplication}})
	web := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "web", Version: "1.0.0", Type: model.PackageTypeApplication}})
	core := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "core", Version: "1.0.0", Type: model.PackageTypeApplication}})
	coreDep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "commons-lang3", Version: "3.12.0"}, Scopes: model.ScopesOf(model.ScopeRuntime)})
	webDep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "jackson-databind", Version: "2.13.0"}, Scopes: model.ScopesOf(model.ScopeRuntime)})
	for _, pkg := range []*model.DependencyNode{parent, web, core, coreDep, webDep} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add node: %v", err)
		}
	}
	// web -> core makes core a non-root module; its direct dep must still be
	// listed as top-level.
	for _, edge := range [][2]string{{web.NodeID(), core.NodeID()}, {web.NodeID(), webDep.NodeID()}, {core.NodeID(), coreDep.NodeID()}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge: %v", err)
		}
	}
	report := render.StripANSI(render.Scan(g, model.NewPackageRegistry(), nil, nil, false, false, false, nil, nil, nil))
	for _, want := range []string{"commons-lang3", "jackson-databind"} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected %q in top-level dependencies, got:\n%s", want, report)
		}
	}
}

// The same case with real module nodes, which is what a workspace member or
// reactor module actually is after ADR-0041.
//
// The test above builds its "modules" as application-typed dependency nodes,
// so it kept passing while the module path was broken: a module that another
// module depends on is not a graph root and is not a dependency node either,
// so it fell out of the top-level parents entirely and its own direct
// dependencies were reported as transitive.
func TestRenderScanReportTopLevelDepsCoverNonRootModuleNodes(t *testing.T) {
	g := model.New()
	web := testnodes.Module("web/pom.xml", "web", "1.0.0")
	core := testnodes.Module("core/pom.xml", "core", "1.0.0")
	coreDep := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{Name: "commons-lang3", Version: "3.12.0"},
		Scopes:      model.ScopesOf(model.ScopeRuntime),
	})
	webDep := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{Name: "jackson-databind", Version: "2.13.0"},
		Scopes:      model.ScopesOf(model.ScopeRuntime),
	})
	for _, node := range []model.GraphNode{web, core, coreDep, webDep} {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("add node: %v", err)
		}
	}
	// web -> core makes core a non-root module; its direct dependency must
	// still be listed as top-level.
	for _, edge := range [][2]string{
		{web.NodeID(), core.NodeID()},
		{web.NodeID(), webDep.NodeID()},
		{core.NodeID(), coreDep.NodeID()},
	} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge: %v", err)
		}
	}
	report := render.StripANSI(render.Scan(g, model.NewPackageRegistry(), nil, nil, false, false, false, nil, nil, nil))
	for _, want := range []string{"commons-lang3", "jackson-databind"} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected %q in top-level dependencies, got:\n%s", want, report)
		}
	}
}

func TestSBOMLifecyclePhase(t *testing.T) {
	cases := map[string]string{
		"filesystem":      "pre-build",
		"git repository":  "pre-build",
		"container image": "post-build",
		"sbom":            "",
		"":                "",
	}
	for in, want := range cases {
		if got := sbomLifecyclePhase(in); got != want {
			t.Errorf("sbomLifecyclePhase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSBOMCompositionAggregate(t *testing.T) {
	if got := sbomCompositionAggregate(model.ScopeUnknown, false); got != "complete" {
		t.Fatalf("unfiltered clean scan should claim complete, got %q", got)
	}
	if got := sbomCompositionAggregate(model.ScopeRuntime, false); got != "incomplete" {
		t.Fatalf("scope-filtered scan must not claim complete, got %q", got)
	}
	if got := sbomCompositionAggregate(model.ScopeUnknown, true); got != "unknown" {
		t.Fatalf("degraded resolution must declare unknown completeness, got %q", got)
	}
}

// TestCoverageDegradedFiltersOnTheWarningKind pins that only a warning that
// degrades coverage counts against completeness and restatement; a
// readiness notice does not.
func TestCoverageDegradedFiltersOnTheWarningKind(t *testing.T) {
	if coverageDegraded(nil) {
		t.Fatal("no warnings must not degrade coverage")
	}
	fallback := plugin.DetectorWarning{Type: plugin.DetectorWarningFallback}
	if !fallback.DegradesCoverage() {
		t.Fatalf("fixture %q must degrade coverage for this test to mean anything", fallback.Type)
	}
	if !coverageDegraded([]plugin.DetectorWarning{fallback}) {
		t.Fatal("a fallback warning must degrade coverage")
	}
	// A package-manager notice says the graph is sound and an install
	// elsewhere may not be; it must not count.
	benign := plugin.DetectorWarning{Type: plugin.DetectorWarningPackageManager}
	if benign.DegradesCoverage() {
		t.Fatalf("fixture %q must keep coverage for this test to mean anything", benign.Type)
	}
	if coverageDegraded([]plugin.DetectorWarning{benign}) {
		t.Fatalf("a %q warning keeps coverage and must not count as degraded", benign.Type)
	}
	if !coverageDegraded([]plugin.DetectorWarning{benign, fallback}) {
		t.Fatal("one degrading warning among benign ones must still count")
	}
}

// TestSBOMRestatesSourceOnlyForAnUntransformedScan pins the predicate that
// lets a single-source export adopt its source's identity (ADR-0042 as
// amended by #433): anything that changed the graph after ingest -- a scope
// filter, enrichment, degraded resolution -- makes the export a different
// document, which mints its own identity and links the source instead.
func TestSBOMRestatesSourceOnlyForAnUntransformedScan(t *testing.T) {
	cases := []struct {
		name     string
		current  config.Resolved
		scope    model.Scope
		degraded bool
		want     bool
	}{
		{name: "plain scan restates", scope: model.ScopeUnknown, want: true},
		{name: "enrichment transforms", current: config.Resolved{Enrich: true}, scope: model.ScopeUnknown, want: false},
		{name: "scope filter transforms", scope: model.ScopeRuntime, want: false},
		{name: "degraded resolution transforms", scope: model.ScopeUnknown, degraded: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sbomRestatesSource(tc.current, tc.scope, tc.degraded); got != tc.want {
				t.Fatalf("sbomRestatesSource(enrich=%v, scope=%q, degraded=%v) = %v, want %v", tc.current.Enrich, tc.scope, tc.degraded, got, tc.want)
			}
		})
	}
}

func TestGitDescribeVersion(t *testing.T) {
	if got := gitDescribeVersion(zap.NewNop(), ""); got != "" {
		t.Fatalf("empty path must yield no version, got %q", got)
	}
	if got := gitDescribeVersion(zap.NewNop(), t.TempDir()); got != "" {
		t.Fatalf("non-git directory must yield no version, got %q", got)
	}
}
