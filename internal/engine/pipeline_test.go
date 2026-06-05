package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

type fakeFallbackDetector struct {
	fakeDetector
	fallback Detector
}

func (f fakeFallbackDetector) FallbackDetector() Detector {
	return f.fallback
}

type recordingProgress struct {
	details []string
}

func (p *recordingProgress) StartStage(string, int)        {}
func (p *recordingProgress) AdvanceStage(string, int, int) {}
func (p *recordingProgress) CompleteStage(string, int)     {}
func (p *recordingProgress) Detail(label, detail string) {
	p.details = append(p.details, label+": "+detail)
}

// ---------------------------------------------------------------------------
// Detector resolution tests
// ---------------------------------------------------------------------------

func TestResolveDetectors_RunsMatchingDetector(t *testing.T) {
	registry := newTestRegistry()
	nativeGraph := sdk.New()
	nativeGraph.AddNode(sdk.NewDependencyRef("app", "1.0.0"))

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-native", Enabled: true, SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(nativeGraph, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{
		Ecosystem:      EcosystemNPM,
		PackageManager: PackageManagerNPM,
	}
	results, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil)
	if err != nil {
		t.Fatalf("resolveDetectors() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].DetectorName != "npm-native" {
		t.Fatalf("expected npm-native result, got %q", results[0].DetectorName)
	}
}

func TestResolveDetectors_ReportsDetectorDetail(t *testing.T) {
	registry := newTestRegistry()
	graph := sdk.New()
	if err := graph.AddNode(sdk.NewDependencyRef("app", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-native", Enabled: true, SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})

	progress := &recordingProgress{}
	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{
		Ecosystem:      EcosystemNPM,
		PackageManager: PackageManagerNPM,
		Subproject: Subproject{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo/app"},
			RelativePath:            ".",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		},
	}

	if _, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), progress); err != nil {
		t.Fatalf("resolveDetectors() error = %v", err)
	}
	if len(progress.details) == 0 {
		t.Fatal("expected detector detail progress")
	}
	if got := progress.details[len(progress.details)-1]; got != "Detecting dependencies: npm-native - app (npm)" {
		t.Fatalf("unexpected detector detail %q", got)
	}
}

func TestResolveDetectors_FallsBackWhenPrimaryFails(t *testing.T) {
	registry := newTestRegistry()
	fallbackGraph := sdk.New()
	fallbackGraph.AddNode(sdk.NewDependencyRef("app", "1.0.0"))

	registry.registerDetector(fakeFallbackDetector{
		fakeDetector: fakeDetector{
			descriptor: DetectorDescriptor{Name: "go-native", Enabled: true, SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
			err:        errors.New("go not installed"),
		},
		fallback: fakeDetector{
			descriptor: DetectorDescriptor{Name: "syft-detector", Enabled: true, SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
			result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackGraph, sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
		},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{
		Ecosystem:      EcosystemGo,
		PackageManager: PackageManagerGoMod,
	}
	results, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil)
	if err != nil {
		t.Fatalf("resolveDetectors() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 fallback result, got %d", len(results))
	}
	if results[0].DetectorName != "syft-detector" {
		t.Fatalf("expected syft-detector result, got %q", results[0].DetectorName)
	}
}

func TestResolveDetectors_DoesNotRunExcludedFallback(t *testing.T) {
	registry := newTestRegistry()
	fallbackGraph := sdk.New()
	fallbackGraph.AddNode(sdk.NewDependencyRef("app", "1.0.0"))

	registry.registerDetector(fakeFallbackDetector{
		fakeDetector: fakeDetector{
			descriptor: DetectorDescriptor{Name: "go-native", Enabled: true, SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
			err:        errors.New("go not installed"),
		},
		fallback: fakeDetector{
			descriptor: DetectorDescriptor{Name: "syft-detector", Enabled: true, SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
			result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackGraph, sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
		},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{
		Ecosystem:      EcosystemGo,
		PackageManager: PackageManagerGoMod,
		DetectorFilter: DetectorFilter{Exclude: []string{"syft-detector"}},
	}
	results, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil)
	if err == nil {
		t.Fatal("expected primary detector error when fallback is excluded")
	}
	if len(results) != 0 {
		t.Fatalf("expected no fallback results, got %#v", results)
	}
}

func TestPipeline_UsesPlannedDetectorChainWithoutEagerFallbackExecution(t *testing.T) {
	registry := newTestRegistry()
	fallbackGraph := sdk.New()
	fallbackGraph.AddNode(sdk.NewDependencyRef("app", "1.0.0"))

	registry.registerDetector(fakeFallbackDetector{
		fakeDetector: fakeDetector{
			descriptor: DetectorDescriptor{
				Name:                "go-native",
				Enabled:             true,
				Origin:              sdk.CoreOrigin,
				SupportedEcosystems: []Ecosystem{EcosystemGo},
				SupportedManagers:   []PackageManager{PackageManagerGoMod},
			},
			err: errors.New("go not installed"),
		},
		fallback: fakeDetector{
			descriptor: DetectorDescriptor{
				Name:      "syft-detector",
				Enabled:   true,
				Origin:    sdk.BundledOrigin,
				Technique: sdk.MultipleTechnique,
			},
			result: ResolveGraphResult{Graphs: SingleGraphContainer(fallbackGraph, sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
		},
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:      "syft-detector",
			Enabled:   true,
			Origin:    sdk.BundledOrigin,
			Technique: sdk.MultipleTechnique,
		},
		result: ResolveGraphResult{Graphs: SingleGraphContainer(fallbackGraph, sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	result, err := pipeline.Run(context.Background(), PipelineRequest{
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "go-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerGoMod},
			Ecosystem:               EcosystemGo,
			PlannedDetectors:        []string{"go-native", "syft-detector"},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	results := result.ResolveResults
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if got := results[0].DetectorName; got != "syft-detector" {
		t.Fatalf("expected actual successful detector to be syft-detector, got %q", got)
	}
}

func TestPipeline_DoesNotEnableDetectorEnrichmentForAuditOnly(t *testing.T) {
	registry := newTestRegistry()
	graph := sdk.New()
	if err := graph.AddNode(sdk.NewDependencyRef("app", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}

	seen := false
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "syft-detector",
			Enabled:             true,
			Origin:              sdk.BundledOrigin,
			Technique:           sdk.MultipleTechnique,
			SupportedEcosystems: []Ecosystem{EcosystemNPM},
			SupportedManagers:   []PackageManager{PackageManagerNPM},
		},
		result: ResolveGraphResult{Graphs: SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
		onResolve: func(req ResolveGraphRequest) {
			seen = true
			if req.EnrichmentEnabled {
				t.Fatalf("expected detector request enrichment to remain disabled for audit-only runs")
			}
		},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	_, err := pipeline.Run(context.Background(), PipelineRequest{
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
		AuditEnabled: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !seen {
		t.Fatal("expected detector to receive resolve request")
	}
}

func TestPipeline_ThreadsEnrichEnabledIntoResolveRequest(t *testing.T) {
	registry := newTestRegistry()
	graph := sdk.New()
	if err := graph.AddNode(sdk.NewDependencyRef("app", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}

	seen := false
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "syft-detector",
			Enabled:             true,
			Origin:              sdk.BundledOrigin,
			Technique:           sdk.MultipleTechnique,
			SupportedEcosystems: []Ecosystem{EcosystemNPM},
			SupportedManagers:   []PackageManager{PackageManagerNPM},
		},
		result: ResolveGraphResult{Graphs: SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
		onResolve: func(req ResolveGraphRequest) {
			seen = true
			if !req.EnrichmentEnabled {
				t.Fatalf("expected detector request enrichment to be enabled")
			}
		},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	_, err := pipeline.Run(context.Background(), PipelineRequest{
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
		EnrichEnabled: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !seen {
		t.Fatal("expected detector to receive resolve request")
	}
}

// ---------------------------------------------------------------------------
// Pipeline hook tests
// ---------------------------------------------------------------------------

type fakePreResolveHook struct {
	descriptor HookDescriptor
	err        error
	executed   bool
}

func (h *fakePreResolveHook) Descriptor() HookDescriptor { return h.descriptor }

func (h *fakePreResolveHook) Execute(_ context.Context, _ PreResolveContext) error {
	h.executed = true
	return h.err
}

type fakePostResolveHook struct {
	descriptor HookDescriptor
	err        error
	executed   bool
}

func (h *fakePostResolveHook) Descriptor() HookDescriptor { return h.descriptor }

func (h *fakePostResolveHook) Execute(_ context.Context, _ PostResolveContext) error {
	h.executed = true
	return h.err
}

func TestPipeline_PreResolveHook_CalledBeforeDetectors(t *testing.T) {
	registry := newTestRegistry()
	hook := &fakePreResolveHook{
		descriptor: HookDescriptor{Name: "test-pre-hook", Priority: 0, Stage: "pre-resolve"},
	}
	registry.RegisterPreResolveHook(hook)

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", Enabled: true, SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(sdk.New(), sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	_, err := pipeline.Run(context.Background(), PipelineRequest{
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !hook.executed {
		t.Fatal("expected pre-resolve hook to be executed")
	}
}

func TestPipeline_PostResolveHook_CalledAfterAudit(t *testing.T) {
	registry := newTestRegistry()
	postHook := &fakePostResolveHook{
		descriptor: HookDescriptor{Name: "test-post-hook", Priority: 0, Stage: "post-resolve"},
	}
	registry.RegisterPostResolveHook(postHook)

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", Enabled: true, SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(sdk.New(), sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	_, err := pipeline.Run(context.Background(), PipelineRequest{
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !postHook.executed {
		t.Fatal("expected post-resolve hook to be executed")
	}
}

func TestPipeline_PreResolveHookError_AbortsPipeline(t *testing.T) {
	registry := newTestRegistry()
	hook := &fakePreResolveHook{
		descriptor: HookDescriptor{Name: "failing-hook", Priority: 0, Stage: "pre-resolve"},
		err:        errors.New("pre-hook failed"),
	}
	registry.RegisterPreResolveHook(hook)

	pipeline := NewPipeline(registry, zap.NewNop())
	_, err := pipeline.Run(context.Background(), PipelineRequest{
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
	})
	if err == nil {
		t.Fatal("expected error from pre-resolve hook")
	}
}

// ---------------------------------------------------------------------------
// Pipeline full run test
// ---------------------------------------------------------------------------

func TestPipeline_Run_ProducesConsolidatedResult(t *testing.T) {
	registry := newTestRegistry()
	g := sdk.New()
	g.AddNode(sdk.NewDependencyRef("app", "1.0.0"))
	g.AddNode(sdk.NewDependencyRef("react", "18.2.0"))
	g.AddEdge("app@1.0.0", "react@18.2.0")

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", Enabled: true, Origin: sdk.CoreOrigin, SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	result, err := pipeline.Run(context.Background(), PipelineRequest{
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.ResolveResults) != 1 {
		t.Fatalf("expected 1 resolve result, got %d", len(result.ResolveResults))
	}
	if result.Graph == nil {
		t.Fatal("expected consolidated graph")
	}
	if result.Graph.Size() == 0 {
		t.Fatal("expected non-empty consolidated graph")
	}
}

func TestPipeline_Run_DeduplicatesAuditFindings(t *testing.T) {
	registry := newTestRegistry()
	g := sdk.New()
	pkg := sdk.NewDependencyWithID("pkg:npm/react@18.2.0", sdk.Dependency{
		Ecosystem: "npm",
		Name:      "react",
		Version:   "18.2.0",
		PURL:      "pkg:npm/react@18.2.0",
	})
	if err := g.AddNode(pkg); err != nil {
		t.Fatalf("add package: %v", err)
	}
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", Enabled: true, SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "severity-policy", Enabled: true},
		result: AuditResult{Findings: []Finding{
			{ID: "CVE-1", VulnerabilityID: "CVE-1", Kind: sdk.FindingKindVulnerability, Source: "osv", PackageRef: pkg.PURL},
			{ID: "CVE-1", VulnerabilityID: "CVE-1", Kind: sdk.FindingKindVulnerability, Source: "grype", PackageRef: pkg.PURL},
		}},
	})

	result, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), PipelineRequest{
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
		AuditEnabled: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected deduped finding, got %#v", result.Findings)
	}
	if result.Findings[0].Source != "grype" {
		t.Fatalf("expected grype finding to win, got %#v", result.Findings[0])
	}
}

func TestPipeline_RunExplain_FocusesSelectedManifestAndAuditsComponent(t *testing.T) {
	registry := newTestRegistry()
	g := sdk.New()
	app := sdk.NewDependencyWithID("pkg:npm/app@1.0.0", sdk.Dependency{Ecosystem: "npm", Name: "app", Version: "1.0.0", PURL: "pkg:npm/app@1.0.0"})
	dep := sdk.NewDependencyWithID("pkg:npm/dep@2.0.0", sdk.Dependency{Ecosystem: "npm", Name: "dep", Version: "2.0.0", PURL: "pkg:npm/dep@2.0.0"})
	if err := g.AddNode(app); err != nil {
		t.Fatalf("add app: %v", err)
	}
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add dep: %v", err)
	}
	if err := g.AddEdge(app.ID, dep.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", Enabled: true, Origin: sdk.CoreOrigin, SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})
	registry.registerMatcher(fakeMatcher{
		name:    "license-checker",
		enabled: true,
		run: func(reg *sdk.PackageRegistry) {
			pkg := reg.Ensure(dep.PURL)
			pkg.Licenses = []sdk.PackageLicense{{SPDXExpression: "MIT"}}
		},
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "severity-policy", Enabled: true},
		run: func(req AuditRequest) AuditResult {
			if req.Target == nil || req.Target.ID != dep.ID {
				t.Fatalf("expected component target %q, got %#v", dep.ID, req.Target)
			}
			return AuditResult{Findings: []Finding{{ID: "CVE-1", VulnerabilityID: "CVE-1", Kind: sdk.FindingKindVulnerability, Source: "osv", PackageRef: req.Target.PURL}}}
		},
	})

	result, err := NewPipeline(registry, zap.NewNop()).RunExplain(context.Background(), ExplainRequest{
		Query: "dep",
		Pipeline: PipelineRequest{
			Subprojects: []Subproject{{
				ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
				RelativePath:            ".",
				PrimaryDetector:         "npm-detector",
				DetectedPackageManagers: []PackageManager{PackageManagerNPM},
				Ecosystem:               EcosystemNPM,
			}},
			EnrichEnabled: true,
			AuditEnabled:  true,
		},
	})
	if err != nil {
		t.Fatalf("RunExplain() error = %v", err)
	}
	if len(result.Targets) != 1 {
		t.Fatalf("expected one explain target, got %#v", result.Targets)
	}
	if result.Registry == nil {
		t.Fatalf("expected explain result to expose package registry")
	}
	pkg, ok := result.Registry.Get(dep.PURL)
	if !ok || len(pkg.Licenses) != 1 {
		t.Fatalf("expected registry to carry matcher-supplied license for %s, got %#v", dep.PURL, pkg)
	}
	if len(result.Targets[0].Findings) != 1 || len(result.Findings) != 1 {
		t.Fatalf("expected component audit findings, target=%#v all=%#v", result.Targets[0].Findings, result.Findings)
	}
	if result.FocusedGraph == nil || result.FocusedGraph.Size() != 2 {
		t.Fatalf("expected focused graph with path packages, got %#v", result.FocusedGraph)
	}
}

func TestPipeline_RunExplain_ReturnsNotFoundWhenQueryIsAbsent(t *testing.T) {
	registry := newTestRegistry()
	g := sdk.New()
	if err := g.AddNode(sdk.NewDependencyWithID("pkg:npm/app@1.0.0", sdk.Dependency{Ecosystem: "npm", Name: "app", Version: "1.0.0"})); err != nil {
		t.Fatalf("add package: %v", err)
	}
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", Enabled: true, SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})

	_, err := NewPipeline(registry, zap.NewNop()).RunExplain(context.Background(), ExplainRequest{
		Query: "missing",
		Pipeline: PipelineRequest{Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}}},
	})
	if err == nil {
		t.Fatal("expected missing dependency error")
	}
}

func TestPipeline_Run_PropagatesMatcherEnrichmentToRegistry(t *testing.T) {
	registry := newTestRegistry()
	const reactPURL = "pkg:npm/react@18.2.0"
	registry.registerMatcher(fakeMatcher{
		name:     "license-checker",
		enabled:  true,
		priority: 100,
		run: func(reg *sdk.PackageRegistry) {
			pkg := reg.Ensure(reactPURL)
			pkg.Licenses = []sdk.PackageLicense{{SPDXExpression: "MIT"}}
			pkg.Metadata = map[string]any{"endoflife.date": map[string]any{"status": "supported"}}
		},
	})

	nativeGraph := sdk.New()
	nativeApp := sdk.NewDependencyWithID("pkg:npm/app@1.0.0", sdk.Dependency{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "app",
		Version:     "1.0.0",
		PURL:        "pkg:npm/app@1.0.0",
	})
	if err := nativeGraph.AddNode(nativeApp); err != nil {
		t.Fatalf("add native app: %v", err)
	}
	nativeReact := sdk.NewDependencyWithID("pkg:npm/react@18.2.0", sdk.Dependency{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "react",
		Version:     "18.2.0",
		PURL:        "pkg:npm/react@18.2.0",
	})
	if err := nativeGraph.AddNode(nativeReact); err != nil {
		t.Fatalf("add native react: %v", err)
	}
	if err := nativeGraph.AddEdge(nativeApp.ID, nativeReact.ID); err != nil {
		t.Fatalf("add native dependency: %v", err)
	}

	sbomGraph := sdk.New()
	if err := sbomGraph.AddNode(sdk.NewDependencyWithID("SPDXRef-app", sdk.Dependency{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "app",
		Version:     "1.0.0",
		PURL:        "pkg:npm/app@1.0.0",
	})); err != nil {
		t.Fatalf("add sbom app: %v", err)
	}
	if err := sbomGraph.AddNode(sdk.NewDependencyWithID("SPDXRef-react", sdk.Dependency{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "react",
		Version:     "18.2.0",
		PURL:        "pkg:npm/react@18.2.0",
	})); err != nil {
		t.Fatalf("add sbom react: %v", err)
	}
	if err := sbomGraph.AddEdge("SPDXRef-app", "SPDXRef-react"); err != nil {
		t.Fatalf("add sbom dependency: %v", err)
	}

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", Enabled: true, Origin: sdk.CoreOrigin, SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(nativeGraph, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "sbom-detector", Enabled: true, Origin: sdk.CoreOrigin, SupportedEcosystems: []Ecosystem{EcosystemSBOM}, SupportedManagers: []PackageManager{PackageManagerSBOM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(sbomGraph, sdk.ManifestMetadata{Path: "app.spdx.json", Kind: "spdx"})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	result, err := pipeline.Run(context.Background(), PipelineRequest{
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
		Subprojects: []Subproject{
			{
				ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
				RelativePath:            ".",
				PrimaryDetector:         "npm-detector",
				DetectedPackageManagers: []PackageManager{PackageManagerNPM},
				Ecosystem:               EcosystemNPM,
			},
			{
				ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
				RelativePath:            "app.spdx.json",
				PrimaryDetector:         "sbom-detector",
				DetectedPackageManagers: []PackageManager{PackageManagerSBOM},
				Ecosystem:               EcosystemSBOM,
			},
		},
		MatchEnabled: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := len(result.Consolidated.Manifests); got != 2 {
		t.Fatalf("expected 2 manifests, got %d", got)
	}
	if result.Registry == nil {
		t.Fatalf("expected pipeline result to expose a registry")
	}
	pkg, ok := result.Registry.Get(reactPURL)
	if !ok || pkg == nil {
		t.Fatalf("expected registry to contain %s, got registry with %d entries", reactPURL, result.Registry.Len())
	}
	if values := pkg.LicenseValues(); len(values) != 1 || values[0] != "MIT" {
		t.Fatalf("expected matcher-supplied license on registry package, got %#v", values)
	}
	if pkg.Metadata == nil {
		t.Fatalf("expected matcher metadata on registry package")
	}
	if _, ok := pkg.Metadata["endoflife.date"]; !ok {
		t.Fatalf("expected endoflife.date metadata to be preserved")
	}
}

// ---------------------------------------------------------------------------
// Registry detector tests
// ---------------------------------------------------------------------------

func TestRegistry_Detectors_RespectsFilter(t *testing.T) {
	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{descriptor: DetectorDescriptor{Name: "npm-native", Enabled: true, SupportedManagers: []PackageManager{PackageManagerNPM}}})
	registry.registerDetector(fakeDetector{descriptor: DetectorDescriptor{Name: "syft-detector", Enabled: true, SupportedManagers: []PackageManager{PackageManagerNPM}}})

	detectors := registry.Detectors(ResolveGraphRequest{
		PackageManager: PackageManagerNPM,
		DetectorFilter: DetectorFilter{Exclude: []string{"syft-detector"}},
	})
	if len(detectors) != 1 {
		t.Fatalf("expected 1 detector after filter, got %d", len(detectors))
	}
	if detectors[0].Descriptor().Name != "npm-native" {
		t.Fatalf("expected npm-native, got %q", detectors[0].Descriptor().Name)
	}
}

func TestRegistry_HooksSortedByPriority(t *testing.T) {
	registry := newTestRegistry()
	hookA := &fakePreResolveHook{descriptor: HookDescriptor{Name: "hook-b", Priority: 10}}
	hookB := &fakePreResolveHook{descriptor: HookDescriptor{Name: "hook-a", Priority: 5}}
	registry.RegisterPreResolveHook(hookA)
	registry.RegisterPreResolveHook(hookB)

	hooks := registry.PreResolveHooks()
	if len(hooks) != 2 {
		t.Fatalf("expected 2 hooks, got %d", len(hooks))
	}
	if hooks[0].Descriptor().Name != "hook-a" {
		t.Fatalf("expected hook-a first (lower priority), got %q", hooks[0].Descriptor().Name)
	}
	if hooks[1].Descriptor().Name != "hook-b" {
		t.Fatalf("expected hook-b second (higher priority), got %q", hooks[1].Descriptor().Name)
	}
}

// ---------------------------------------------------------------------------
// PipelineWarningsFromError / parseWarningSource
// ---------------------------------------------------------------------------

func TestParseWarningSource(t *testing.T) {
	tests := []struct {
		text, prefix        string
		wantSource, wantMsg string
	}{
		{"detector go-mod: not ready", "detector", "go-mod", "not ready"},
		{"auditor grype: applicability check failed", "auditor", "grype", "applicability check failed"},
		{"matcher license-checker: not applicable", "matcher", "license-checker", "not applicable"},
		{"subproject . (go/go): no chain", "detector", "", "subproject . (go/go): no chain"},
		{"unrelated error text", "detector", "", "unrelated error text"},
		{"detector nocolon", "detector", "", "detector nocolon"},
	}
	for _, tt := range tests {
		source, msg := parseWarningSource(tt.text, tt.prefix)
		if source != tt.wantSource || msg != tt.wantMsg {
			t.Errorf("parseWarningSource(%q, %q) = (%q, %q), want (%q, %q)",
				tt.text, tt.prefix, source, msg, tt.wantSource, tt.wantMsg)
		}
	}
}

func TestPipelineWarningsFromError_Nil(t *testing.T) {
	got := PipelineWarningsFromError(nil, "detector")
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestPipelineWarningsFromError_JoinedErrors(t *testing.T) {
	err := errors.Join(
		errors.New("auditor osv: timeout"),
		errors.New("auditor grype: not ready"),
	)
	warnings := PipelineWarningsFromError(err, "auditor")
	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(warnings))
	}
	if warnings[0].Source != "osv" || warnings[0].Message != "timeout" {
		t.Errorf("warning[0] = %+v", warnings[0])
	}
	if warnings[1].Source != "grype" || warnings[1].Message != "not ready" {
		t.Errorf("warning[1] = %+v", warnings[1])
	}
}
