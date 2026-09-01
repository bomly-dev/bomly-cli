package engine

import (
	"context"
	"errors"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

type fakeRemediationDetector struct {
	fakeDetector
	hints sdk.RemediationHintResponse
}

func (f fakeRemediationDetector) RemediationHints(
	context.Context,
	sdk.RemediationHintRequest,
) (sdk.RemediationHintResponse, error) {
	return f.hints, nil
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
	if err := nativeGraph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-native", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
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
	if err := graph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-native", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
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
	if err := fallbackGraph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "go-native", SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
		err:        errors.New("go not installed"),
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "syft-detector", SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackGraph, sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
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
	if err := fallbackGraph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "go-native", SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
		err:        errors.New("go not installed"),
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "syft-detector", SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackGraph, sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
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

func TestResolveDetectors_IncludesReadyReasonWhenDetectorNotReady(t *testing.T) {
	registry := newTestRegistry()
	notReady := false
	registry.registerDetector(fakeDetector{
		descriptor:  DetectorDescriptor{Name: "maven-detector", SupportedEcosystems: []Ecosystem{EcosystemMaven}, SupportedManagers: []PackageManager{PackageManagerMaven}},
		ready:       &notReady,
		readyReason: "java runtime is unavailable: Unable to locate a Java Runtime",
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{
		Ecosystem:      EcosystemMaven,
		PackageManager: PackageManagerMaven,
	}
	_, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil)
	if err == nil {
		t.Fatal("expected detector readiness error")
	}
	// A chain that never started reports one actionable line naming each link
	// and what it needs, not a joined list of per-detector errors.
	if !strings.Contains(err.Error(), "no usable detector: maven-detector not ready (java runtime is unavailable") {
		t.Fatalf("expected readiness reason in error, got %v", err)
	}
}

// TestResolveDetectors_SummarizesEveryUnreadyChainLink covers the fallback
// chain: when neither the primary nor its fallback can run, both are named.
func TestResolveDetectors_SummarizesEveryUnreadyChainLink(t *testing.T) {
	registry := newTestRegistry()
	notReady := false
	registry.registerDetector(fakeDetector{
		descriptor:  DetectorDescriptor{Name: "npm-native", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		ready:       &notReady,
		readyReason: "npm not on PATH",
	})
	registry.registerDetector(fakeDetector{
		descriptor:  DetectorDescriptor{Name: "npm-lockfile", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		ready:       &notReady,
		readyReason: "no committed lockfile",
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM}
	_, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil)
	if err == nil {
		t.Fatal("expected detector readiness error")
	}
	want := "no usable detector: npm-native not ready (npm not on PATH); npm-lockfile not ready (no committed lockfile)"
	if err.Error() != want {
		t.Fatalf("resolveDetectors() error = %q, want %q", err, want)
	}
}

// TestResolveDetectors_KeepsRunFailuresVerbatim proves the summary is scoped
// to readiness: a detector that ran and failed explains itself better than a
// "no usable detector" line would.
func TestResolveDetectors_KeepsRunFailuresVerbatim(t *testing.T) {
	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-native", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		err:        errors.New("npm ls: exit status 1"),
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM}
	_, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil)
	if err == nil {
		t.Fatal("expected detector resolution error")
	}
	if strings.Contains(err.Error(), "no usable detector") {
		t.Fatalf("expected the run failure verbatim, got %v", err)
	}
	if !strings.Contains(err.Error(), "npm ls: exit status 1") {
		t.Fatalf("expected the underlying failure in the error, got %v", err)
	}
}

func TestPipeline_UsesPlannedDetectorChainWithoutEagerFallbackExecution(t *testing.T) {
	registry := newTestRegistry()
	fallbackGraph := sdk.New()
	if err := fallbackGraph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "go-native",
			SupportedEcosystems: []Ecosystem{EcosystemGo},
			SupportedManagers:   []PackageManager{PackageManagerGoMod},
		},
		err: errors.New("go not installed"),
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:      "syft-detector",
			Technique: sdk.MultipleTechnique,
		},
		result: ResolveGraphResult{Graphs: SingleGraphContainer(fallbackGraph, sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:      "syft-detector",
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
	if err := graph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}

	seen := false
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "syft-detector",
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
		FindingPolicyResolvers: []sdk.FindingPolicyResolver{
			fixedPolicyResolver{status: sdk.FindingPolicyStatusSuppressed},
		},
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
	if err := graph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}

	seen := false
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "syft-detector",
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

func TestPipeline_ThreadsScopeFilterIntoPrimaryAndFiltersResult(t *testing.T) {
	registry := newTestRegistry()
	graph := scopedTestGraph(t)

	seen := false
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "npm-detector",
			SupportedEcosystems: []Ecosystem{EcosystemNPM},
			SupportedManagers:   []PackageManager{PackageManagerNPM},
		},
		result: ResolveGraphResult{Graphs: SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
		onResolve: func(req ResolveGraphRequest) {
			seen = true
			if req.ScopeFilter != sdk.ScopeDevelopment {
				t.Fatalf("expected development scope in detector request, got %q", req.ScopeFilter)
			}
		},
	})

	result, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), PipelineRequest{
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
		ScopeFilter: sdk.ScopeDevelopment,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !seen {
		t.Fatal("expected detector to receive resolve request")
	}
	if _, ok := result.Graph.Node("pkg:npm/vitest@2.0.0"); !ok {
		t.Fatalf("expected development dependency to remain: %s", result.Graph.PrettyString())
	}
	if _, ok := result.Graph.Node("pkg:npm/react@18.2.0"); ok {
		t.Fatalf("expected runtime dependency to be filtered: %s", result.Graph.PrettyString())
	}
}

func TestPipeline_ThreadsScopeFilterIntoFallbackDetector(t *testing.T) {
	registry := newTestRegistry()
	fallbackGraph := scopedTestGraph(t)

	seenFallback := false
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-native", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		err:        errors.New("native failed"),
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-lockfile", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackGraph, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
		onResolve: func(req ResolveGraphRequest) {
			seenFallback = true
			if req.ScopeFilter != sdk.ScopeRuntime {
				t.Fatalf("expected runtime scope in fallback request, got %q", req.ScopeFilter)
			}
		},
	})

	results, err := NewPipeline(registry, zap.NewNop()).resolveDetectors(context.Background(), ResolveGraphRequest{
		Ecosystem:      EcosystemNPM,
		PackageManager: PackageManagerNPM,
		ScopeFilter:    sdk.ScopeRuntime,
	}, registry.Detectors(ResolveGraphRequest{PackageManager: PackageManagerNPM}), nil)
	if err != nil {
		t.Fatalf("resolveDetectors() error = %v", err)
	}
	if !seenFallback {
		t.Fatal("expected fallback detector to receive resolve request")
	}
	graph, err := results[0].ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if _, ok := testnodes.Find(graph, "react@18.2.0"); !ok {
		t.Fatalf("expected runtime dependency to remain: %s", graph.PrettyString())
	}
	if _, ok := testnodes.Find(graph, "vitest@2.0.0"); ok {
		t.Fatalf("expected development dependency to be filtered: %s", graph.PrettyString())
	}
}

func TestPipeline_ThreadsScopeFilterIntoInstallFirstDetector(t *testing.T) {
	registry := newTestRegistry()
	graph := scopedTestGraph(t)
	detector := &fakeInstallFirstDetector{
		fakeDetector: fakeDetector{
			descriptor: DetectorDescriptor{
				Name:                 "pip-detector",
				SupportedEcosystems:  []Ecosystem{sdk.EcosystemPython},
				SupportedManagers:    []PackageManager{sdk.PackageManagerPip},
				SupportsInstallFirst: true,
			},
			result: ResolveGraphResult{Graphs: SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "requirements.txt", Kind: "requirements.txt"})},
		},
		onInstall: func(req ResolveGraphRequest) {
			if req.ScopeFilter != sdk.ScopeRuntime {
				t.Fatalf("expected runtime scope in install-first request, got %q", req.ScopeFilter)
			}
		},
	}
	registry.registerDetector(detector)

	if _, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), PipelineRequest{
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "pip-detector",
			DetectedPackageManagers: []PackageManager{sdk.PackageManagerPip},
			Ecosystem:               sdk.EcosystemPython,
		}},
		ScopeFilter:  sdk.ScopeRuntime,
		InstallFirst: true,
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !detector.installed {
		t.Fatal("expected install-first detector to install")
	}
}

func scopedTestGraph(t *testing.T) *sdk.Graph {
	t.Helper()
	graph := sdk.New()
	app := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "app", Version: "1.0.0", Type: sdk.PackageTypeApplication}})
	runtimeDep := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "react", Version: "18.2.0", PURL: "pkg:npm/react@18.2.0"}, Scopes: sdk.ScopesOf(sdk.ScopeRuntime)})
	devDep := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "vitest", Version: "2.0.0", PURL: "pkg:npm/vitest@2.0.0"}, Scopes: sdk.ScopesOf(sdk.ScopeDevelopment)})
	for _, dep := range []*sdk.DependencyNode{app, runtimeDep, devDep} {
		if err := graph.AddNode(dep); err != nil {
			t.Fatalf("add %q: %v", dep.NodeID(), err)
		}
	}
	if err := graph.AddEdge(app.NodeID(), runtimeDep.NodeID()); err != nil {
		t.Fatalf("add runtime edge: %v", err)
	}
	if err := graph.AddEdge(app.NodeID(), devDep.NodeID()); err != nil {
		t.Fatalf("add development edge: %v", err)
	}
	return graph
}

// ---------------------------------------------------------------------------
// Pipeline full run test
// ---------------------------------------------------------------------------

func TestPipeline_Run_ProducesConsolidatedResult(t *testing.T) {
	registry := newTestRegistry()
	g := sdk.New()
	if err := g.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	if err := g.AddNode(testnodes.Ref("react", "18.2.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	if err := g.AddEdge(testnodes.ID(g, "app@1.0.0"), testnodes.ID(g, "react@18.2.0")); err != nil {
		t.Fatalf("add edge: %v", err)
	}

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
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

func TestPipeline_Run_DerivesCanonicalRemediationAtEndOfEnrichment(t *testing.T) {
	const purl = "pkg:npm/react@18.2.0"
	registry := newTestRegistry()
	graph := sdk.New()
	root := testnodes.DepFrom(sdk.DependencyNode{
		Coordinates: sdk.Coordinates{
			Name:           "app",
			Type:           sdk.PackageTypeApplication,
			PackageManager: sdk.PackageManagerNPM,
		},
		Relationship: sdk.DependencyRelationshipDirect,
		Source:       sdk.DependencySourceProject,
	})
	dependency := testnodes.DepFrom(sdk.DependencyNode{
		Coordinates: sdk.Coordinates{
			Name:           "react",
			Version:        "18.2.0",
			PURL:           purl,
			PackageManager: sdk.PackageManagerNPM,
		},
		Relationship: sdk.DependencyRelationshipDirect,
		Source:       sdk.DependencySourceRegistry,
		PackageRef:   purl,
	})
	for _, node := range []*sdk.DependencyNode{root, dependency} {
		if err := graph.AddNode(node); err != nil {
			t.Fatalf("AddNode(%s) error = %v", node.NodeID(), err)
		}
	}
	if err := graph.AddEdge(root.NodeID(), dependency.NodeID()); err != nil {
		t.Fatalf("AddEdge() error = %v", err)
	}
	registry.registerDetector(fakeRemediationDetector{
		fakeDetector: fakeDetector{
			descriptor: DetectorDescriptor{
				Name:                "npm-detector",
				SupportedEcosystems: []Ecosystem{EcosystemNPM},
				SupportedManagers:   []PackageManager{PackageManagerNPM},
				RemediationCapabilities: []sdk.RemediationCapability{{
					SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
					Actions:           []sdk.RemediationAction{sdk.RemediationActionDirectBump},
				}},
			},
			result: ResolveGraphResult{Graphs: SingleGraphContainer(
				graph,
				sdk.ManifestMetadata{Path: "/repo/package-lock.json", Kind: "package-lock.json"},
			)},
		},
		hints: sdk.RemediationHintResponse{Hints: []sdk.RemediationHint{{
			DependencyRef: dependency.NodeID(),
			ManifestPath:  "/repo/package-lock.json",
			Strategies: []sdk.RemediationStrategyHint{{
				Action: sdk.RemediationActionDirectBump,
			}},
		}}},
	})
	registry.registerMatcher(fakeMatcher{
		name: "vulnerability-matcher",
		run: func(packages *sdk.PackageRegistry) {
			packages.Ensure(purl).Vulnerabilities = []sdk.Vulnerability{{
				ID:      "GHSA-example",
				FixedIn: "19.0.0",
			}}
		},
	})

	result, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), PipelineRequest{
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
	pkg, ok := result.Registry.Get(purl)
	if !ok || pkg.Remediation == nil {
		t.Fatalf("canonical remediation missing: %#v", pkg)
	}
	if pkg.Remediation.Status != sdk.PackageRemediationComplete ||
		pkg.Remediation.RecommendedVersion != "19.0.0" ||
		len(pkg.Remediation.Suggestions) != 1 ||
		pkg.Remediation.Suggestions[0].Action != sdk.RemediationActionDirectBump ||
		pkg.Remediation.Suggestions[0].ManifestPath != "package-lock.json" {
		t.Fatalf("canonical remediation = %#v; warnings = %#v", pkg.Remediation, result.MatchWarnings)
	}
}

func TestPipeline_Run_DeduplicatesAuditFindings(t *testing.T) {
	registry := newTestRegistry()
	g := sdk.New()
	pkg := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		Name:    "react",
		Version: "18.2.0",
		PURL:    "pkg:npm/react@18.2.0"},
	})
	if err := g.AddNode(pkg); err != nil {
		t.Fatalf("add package: %v", err)
	}
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "severity-policy"},
		result: AuditResult{Findings: []Finding{
			{ID: "CVE-1", VulnerabilityID: "CVE-1", Kind: sdk.FindingKindVulnerability, Source: "osv", PackageRef: pkg.NodeID()},
			{ID: "CVE-1", VulnerabilityID: "CVE-1", Kind: sdk.FindingKindVulnerability, Source: "grype", PackageRef: pkg.NodeID()},
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
		FindingPolicyResolvers: []sdk.FindingPolicyResolver{
			fixedPolicyResolver{status: sdk.FindingPolicyStatusSuppressed},
		},
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
	if result.Findings[0].PolicyStatus != sdk.FindingPolicyStatusSuppressed {
		t.Fatalf("expected scan audit policy resolver to suppress finding, got %#v", result.Findings[0])
	}
}

func TestPipeline_RunExplain_FocusesSelectedManifestAndAuditsComponent(t *testing.T) {
	registry := newTestRegistry()
	g := sdk.New()
	app := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "app", Version: "1.0.0", PURL: "pkg:npm/app@1.0.0"}})
	dep := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "dep", Version: "2.0.0", PURL: "pkg:npm/dep@2.0.0"}})
	if err := g.AddNode(app); err != nil {
		t.Fatalf("add app: %v", err)
	}
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add dep: %v", err)
	}
	if err := g.AddEdge(app.NodeID(), dep.NodeID()); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})
	registry.registerMatcher(fakeMatcher{
		name: "license-matcher",
		run: func(reg *sdk.PackageRegistry) {
			pkg := reg.Ensure(dep.NodeID())
			pkg.Licenses = []sdk.PackageLicense{{SPDXExpression: "MIT"}}
		},
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "severity-policy"},
		run: func(req AuditRequest) AuditResult {
			if req.Target == nil || !testnodes.Is(req.Target, dep.NodeID()) {
				t.Fatalf("expected component target %q, got %#v", dep.NodeID(), req.Target)
			}
			return AuditResult{Findings: []Finding{{ID: "CVE-1", VulnerabilityID: "CVE-1", Kind: sdk.FindingKindVulnerability, Source: "osv", PackageRef: req.Target.NodeID()}}}
		},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	request := ExplainRequest{
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
			FindingPolicyResolvers: []sdk.FindingPolicyResolver{
				fixedPolicyResolver{status: sdk.FindingPolicyStatusSuppressed},
			},
		},
	}
	result, err := pipeline.RunExplain(context.Background(), request)
	if err != nil {
		t.Fatalf("RunExplain() error = %v", err)
	}
	if len(result.Targets) != 1 {
		t.Fatalf("expected one explain target, got %#v", result.Targets)
	}
	if result.Registry == nil {
		t.Fatalf("expected explain result to expose package registry")
	}
	pkg, ok := result.Registry.Get(dep.NodeID())
	if !ok || len(pkg.Licenses) != 1 {
		t.Fatalf("expected registry to carry matcher-supplied license for %s, got %#v", dep.NodeID(), pkg)
	}
	if len(result.Targets[0].Findings) != 1 || len(result.Findings) != 1 {
		t.Fatalf("expected component audit findings, target=%#v all=%#v", result.Targets[0].Findings, result.Findings)
	}
	if result.Findings[0].PolicyStatus != sdk.FindingPolicyStatusSuppressed || result.Targets[0].Findings[0].PolicyStatus != sdk.FindingPolicyStatusSuppressed {
		t.Fatalf("explain findings did not apply audit policy resolver: target=%#v all=%#v", result.Targets[0].Findings, result.Findings)
	}
	if result.FocusedGraph == nil || result.FocusedGraph.Size() != 2 {
		t.Fatalf("expected focused graph with path packages, got %#v", result.FocusedGraph)
	}

	request.Pipeline.FindingPolicyResolvers = nil
	request.Pipeline.WarnOnly = true
	warnOnly, err := pipeline.RunExplain(context.Background(), request)
	if err != nil {
		t.Fatalf("RunExplain(warn-only) error = %v", err)
	}
	if len(warnOnly.Findings) != 1 || warnOnly.Findings[0].PolicyStatus != sdk.FindingPolicyStatusWarn {
		t.Fatalf("explain warn-only findings = %#v", warnOnly.Findings)
	}
}

func TestPipeline_RunExplain_ReturnsNotFoundWhenQueryIsAbsent(t *testing.T) {
	registry := newTestRegistry()
	g := sdk.New()
	if err := g.AddNode(testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "app", Version: "1.0.0"}})); err != nil {
		t.Fatalf("add package: %v", err)
	}
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
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

func TestPipeline_RunExplain_UsesScopedDetectionResult(t *testing.T) {
	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(scopedTestGraph(t), sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})

	baseReq := PipelineRequest{
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
		ScopeFilter: sdk.ScopeDevelopment,
	}
	result, err := NewPipeline(registry, zap.NewNop()).RunExplain(context.Background(), ExplainRequest{
		Query:    "vitest",
		Pipeline: baseReq,
	})
	if err != nil {
		t.Fatalf("RunExplain() error = %v", err)
	}
	if len(result.Targets) != 1 {
		t.Fatalf("expected one development target, got %#v", result.Targets)
	}

	_, err = NewPipeline(registry, zap.NewNop()).RunExplain(context.Background(), ExplainRequest{
		Query:    "react",
		Pipeline: baseReq,
	})
	if err == nil {
		t.Fatal("expected runtime dependency to be absent from development-scoped explain")
	}
}

func TestPipeline_Run_PropagatesMatcherEnrichmentToRegistry(t *testing.T) {
	registry := newTestRegistry()
	const reactPURL = "pkg:npm/react@18.2.0"
	registry.registerMatcher(fakeMatcher{
		name: "license-matcher",
		run: func(reg *sdk.PackageRegistry) {
			pkg := reg.Ensure(reactPURL)
			pkg.Licenses = []sdk.PackageLicense{{SPDXExpression: "MIT"}}
			pkg.Metadata = map[string]any{"endoflife.date": map[string]any{"status": "supported"}}
		},
	})

	nativeGraph := sdk.New()
	nativeApp := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		PackageManager: "npm",
		Name:           "app",
		Version:        "1.0.0",
		PURL:           "pkg:npm/app@1.0.0"},
	})
	if err := nativeGraph.AddNode(nativeApp); err != nil {
		t.Fatalf("add native app: %v", err)
	}
	nativeReact := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		PackageManager: "npm",
		Name:           "react",
		Version:        "18.2.0",
		PURL:           "pkg:npm/react@18.2.0"},
	})
	if err := nativeGraph.AddNode(nativeReact); err != nil {
		t.Fatalf("add native react: %v", err)
	}
	if err := nativeGraph.AddEdge(nativeApp.NodeID(), nativeReact.NodeID()); err != nil {
		t.Fatalf("add native dependency: %v", err)
	}

	sbomGraph := sdk.New()
	if err := sbomGraph.AddNode(testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		PackageManager: "npm",
		Name:           "app",
		Version:        "1.0.0",
		PURL:           "pkg:npm/app@1.0.0"},
	})); err != nil {
		t.Fatalf("add sbom app: %v", err)
	}
	if err := sbomGraph.AddNode(testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		PackageManager: "npm",
		Name:           "react",
		Version:        "18.2.0",
		PURL:           "pkg:npm/react@18.2.0"},
	})); err != nil {
		t.Fatalf("add sbom react: %v", err)
	}
	// The SPDXRef- IDs the document used are not node IDs any more; the nodes
	// carry the package URLs those refs described.
	if err := sbomGraph.AddEdge("pkg:npm/app@1.0.0", "pkg:npm/react@18.2.0"); err != nil {
		t.Fatalf("add sbom dependency: %v", err)
	}

	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(nativeGraph, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "sbom-detector", SupportedEcosystems: []Ecosystem{EcosystemSBOM}, SupportedManagers: []PackageManager{PackageManagerSBOM}},
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
	registry.registerDetector(fakeDetector{descriptor: DetectorDescriptor{Name: "npm-native", SupportedManagers: []PackageManager{PackageManagerNPM}}})
	registry.registerDetector(fakeDetector{descriptor: DetectorDescriptor{Name: "syft-detector", SupportedManagers: []PackageManager{PackageManagerNPM}}})

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
		{"matcher license-matcher: not applicable", "matcher", "license-matcher", "not applicable"},
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

func TestPipeline_Run_CollectsDetectorReportedWarnings(t *testing.T) {
	registry := newTestRegistry()
	graph := sdk.New()
	if err := graph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	warning := sdk.DetectorWarning{
		Type:     sdk.DetectorWarningPackageManager,
		Code:     sdk.DetectorWarningCodeInstallGate,
		Source:   "pnpm",
		Manifest: "pnpm-workspace.yaml",
		Message:  "pnpm-workspace.yaml sets minimumReleaseAge=1440 (24h)",
	}
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "pnpm-lockfile", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerPNPM}},
		result: ResolveGraphResult{
			Graphs:   SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "pnpm-lock.yaml", Kind: "pnpm-lock.yaml"}),
			Warnings: []sdk.DetectorWarning{warning},
		},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	result, err := pipeline.Run(context.Background(), PipelineRequest{
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            "apps/web",
			PrimaryDetector:         "pnpm-lockfile",
			DetectedPackageManagers: []PackageManager{PackageManagerPNPM},
			Ecosystem:               EcosystemNPM,
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.DetectorWarnings) != 1 {
		t.Fatalf("expected 1 detector warning, got %+v", result.DetectorWarnings)
	}
	got := result.DetectorWarnings[0]
	// The engine stamps the subproject; everything else passes through.
	if got.Subproject != "apps/web" || got.Source != "pnpm" || got.Message != warning.Message {
		t.Fatalf("unexpected detector warning: %+v", got)
	}
	if got.DegradesCoverage() {
		t.Fatal("a package-manager warning must not claim degraded coverage")
	}
}

func TestPipeline_Run_DeduplicatesRepeatedDetectorWarnings(t *testing.T) {
	registry := newTestRegistry()
	graph := sdk.New()
	if err := graph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	warning := sdk.DetectorWarning{
		Type:    sdk.DetectorWarningPackageManager,
		Code:    sdk.DetectorWarningCodeInstallGate,
		Source:  "npm",
		Message: ".npmrc sets before=2026-01-01",
	}
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-lockfile", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result: ResolveGraphResult{
			Graphs:   SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "package-lock.json"}),
			Warnings: []sdk.DetectorWarning{warning, warning},
		},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	result, err := pipeline.Run(context.Background(), PipelineRequest{
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-lockfile",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.DetectorWarnings) != 1 {
		t.Fatalf("expected the repeated warning to collapse to 1, got %+v", result.DetectorWarnings)
	}
}

func TestPipeline_Run_TypesFallbackWarningsAsDegradedCoverage(t *testing.T) {
	registry := newTestRegistry()
	fallbackGraph := sdk.New()
	if err := fallbackGraph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "maven-detector", SupportedEcosystems: []Ecosystem{EcosystemMaven}, SupportedManagers: []PackageManager{PackageManagerMaven}},
		err:        errors.New("java executable not found on PATH"),
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "syft-detector", SupportedEcosystems: []Ecosystem{EcosystemMaven}, SupportedManagers: []PackageManager{PackageManagerMaven}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackGraph, sdk.ManifestMetadata{Path: "pom.xml", Kind: "pom.xml"})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	result, err := pipeline.Run(context.Background(), PipelineRequest{
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "maven-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerMaven},
			Ecosystem:               EcosystemMaven,
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.DetectorWarnings) != 1 {
		t.Fatalf("expected 1 fallback warning, got %+v", result.DetectorWarnings)
	}
	got := result.DetectorWarnings[0]
	if got.Type != sdk.DetectorWarningFallback || got.Source != "maven-detector" || got.Manifest != "pom.xml" {
		t.Fatalf("unexpected fallback warning: %+v", got)
	}
	if !got.DegradesCoverage() {
		t.Fatal("a fallback warning must report degraded coverage")
	}
	if !strings.Contains(got.Message, "transitive dependencies may be missing") {
		t.Fatalf("fallback warning lost its consequence: %q", got.Message)
	}
}
