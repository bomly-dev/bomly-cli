package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func fallbackTestGraph(t *testing.T) *sdk.Graph {
	t.Helper()
	graph := sdk.New()
	if err := graph.AddNode(testnodes.Ref("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	return graph
}

func TestResolveDetectors_FallbackAnnotatesResult(t *testing.T) {
	registry := newTestRegistry()
	notReady := false
	registry.registerDetector(fakeDetector{
		descriptor:  DetectorDescriptor{Name: "go-native", SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
		ready:       &notReady,
		readyReason: "go executable not found on PATH",
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "syft-detector", SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackTestGraph(t), sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{Ecosystem: EcosystemGo, PackageManager: PackageManagerGoMod}
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
	if results[0].FallbackFrom != "go-native" {
		t.Fatalf("expected fallback provenance from go-native, got %q", results[0].FallbackFrom)
	}
	if want := "not ready: go executable not found on PATH"; results[0].FallbackReason != want {
		t.Fatalf("expected fallback reason %q, got %q", want, results[0].FallbackReason)
	}
	resolution := results[0].Graphs.Entries[0].Manifest.Resolution
	if resolution == nil || resolution.Fallback == nil {
		t.Fatalf("expected entry manifest resolution fallback, got %#v", resolution)
	}
	if resolution.Fallback.From != "go-native" || !strings.Contains(resolution.Fallback.Reason, "go executable not found") {
		t.Fatalf("unexpected entry fallback %#v", resolution.Fallback)
	}
}

func TestResolveDetectors_FallbackPreservesDetectorResolutionMetadata(t *testing.T) {
	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "pip-detector", SupportedEcosystems: []Ecosystem{sdk.EcosystemPython}, SupportedManagers: []PackageManager{sdk.PackageManagerPip}},
		err:        errors.New("pip inspect failed"),
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "syft-detector", SupportedEcosystems: []Ecosystem{sdk.EcosystemPython}, SupportedManagers: []PackageManager{sdk.PackageManagerPip}},
		result: ResolveGraphResult{Graphs: SingleGraphContainer(fallbackTestGraph(t), sdk.ManifestMetadata{
			Path:       "requirements.txt",
			Kind:       sdk.ManifestKindRequirementsTXT,
			Resolution: &sdk.ResolutionMetadata{Method: sdk.ResolutionMethodManifestOnly},
		})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{Ecosystem: sdk.EcosystemPython, PackageManager: sdk.PackageManagerPip}
	results, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil)
	if err != nil {
		t.Fatalf("resolveDetectors() error = %v", err)
	}
	resolution := results[0].Graphs.Entries[0].Manifest.Resolution
	if resolution == nil || resolution.Method != sdk.ResolutionMethodManifestOnly {
		t.Fatalf("expected detector-owned resolution method to survive, got %#v", resolution)
	}
	if resolution.Fallback == nil || resolution.Fallback.From != "pip-detector" {
		t.Fatalf("expected fallback annotation alongside method, got %#v", resolution.Fallback)
	}
}

func TestResolveDetectors_NotApplicableFallbackNotAnnotated(t *testing.T) {
	registry := newTestRegistry()
	notApplicable := false
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-lockfile", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		applicable: &notApplicable,
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-native", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackTestGraph(t), sdk.ManifestMetadata{Path: "package.json", Kind: "package.json"})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM}
	results, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil)
	if err != nil {
		t.Fatalf("resolveDetectors() error = %v", err)
	}
	if results[0].FallbackFrom != "" || results[0].FallbackReason != "" {
		t.Fatalf("expected routine applicability hand-off to remain unannotated, got %q / %q", results[0].FallbackFrom, results[0].FallbackReason)
	}
	if resolution := results[0].Graphs.Entries[0].Manifest.Resolution; resolution != nil && resolution.Fallback != nil {
		t.Fatalf("expected no entry fallback annotation, got %#v", resolution.Fallback)
	}
}

func TestResolveDetectors_ChainedFallbackKeepsOutermostFailure(t *testing.T) {
	registerChain := func(t *testing.T, registry *Registry, outerNotApplicable bool) {
		t.Helper()
		outer := fakeDetector{
			descriptor: DetectorDescriptor{Name: "npm-lockfile", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		}
		if outerNotApplicable {
			notApplicable := false
			outer.applicable = &notApplicable
		} else {
			outer.err = errors.New("lockfile corrupt")
		}
		registry.registerDetector(outer)
		registry.registerDetector(fakeDetector{
			descriptor: DetectorDescriptor{Name: "npm-native", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
			err:        errors.New("npm not installed"),
		})
		registry.registerDetector(fakeDetector{
			descriptor: DetectorDescriptor{Name: "syft-detector", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
			result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackTestGraph(t), sdk.ManifestMetadata{Path: "package.json", Kind: "package.json"})},
		})
	}

	t.Run("outermost real failure wins", func(t *testing.T) {
		registry := newTestRegistry()
		registerChain(t, registry, false)
		pipeline := NewPipeline(registry, zap.NewNop())
		req := ResolveGraphRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM}
		results, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil)
		if err != nil {
			t.Fatalf("resolveDetectors() error = %v", err)
		}
		if results[0].FallbackFrom != "npm-lockfile" {
			t.Fatalf("expected outermost failure npm-lockfile to win, got %q", results[0].FallbackFrom)
		}
		if !strings.Contains(results[0].FallbackReason, "lockfile corrupt") {
			t.Fatalf("expected outermost reason, got %q", results[0].FallbackReason)
		}
	})

	t.Run("not-applicable outer keeps inner failure", func(t *testing.T) {
		registry := newTestRegistry()
		registerChain(t, registry, true)
		pipeline := NewPipeline(registry, zap.NewNop())
		req := ResolveGraphRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM}
		results, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil)
		if err != nil {
			t.Fatalf("resolveDetectors() error = %v", err)
		}
		if results[0].FallbackFrom != "npm-native" {
			t.Fatalf("expected inner failure npm-native to survive, got %q", results[0].FallbackFrom)
		}
		if !strings.Contains(results[0].FallbackReason, "npm not installed") {
			t.Fatalf("expected inner reason, got %q", results[0].FallbackReason)
		}
	})
}

func TestPipeline_RunRecordsFallbackWarning(t *testing.T) {
	registry := newTestRegistry()
	notReady := false
	registry.registerDetector(fakeDetector{
		descriptor:  DetectorDescriptor{Name: "maven-detector", SupportedEcosystems: []Ecosystem{EcosystemMaven}, SupportedManagers: []PackageManager{PackageManagerMaven}},
		ready:       &notReady,
		readyReason: "java executable not found on PATH",
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "syft-detector", SupportedEcosystems: []Ecosystem{EcosystemMaven}, SupportedManagers: []PackageManager{PackageManagerMaven}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackTestGraph(t), sdk.ManifestMetadata{Path: "pom.xml", Kind: sdk.ManifestKindPomXML})},
	})

	core, observed := observer.New(zapcore.WarnLevel)
	pipeline := NewPipeline(registry, zap.New(core))
	result, err := pipeline.Run(context.Background(), PipelineRequest{
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
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
		t.Fatalf("expected exactly one detector warning, got %#v", result.DetectorWarnings)
	}
	warning := result.DetectorWarnings[0]
	if warning.Source != "maven-detector" {
		t.Fatalf("expected warning source maven-detector, got %q", warning.Source)
	}
	if want := "maven-detector unavailable (not ready: java executable not found on PATH) — resolved with syft-detector; transitive dependencies may be missing"; warning.Message != want {
		t.Fatalf("unexpected warning message:\n got %q\nwant %q", warning.Message, want)
	}
	if warning.Type != sdk.DetectorWarningFallback || !warning.DegradesCoverage() {
		t.Fatalf("expected a coverage-degrading fallback warning, got %+v", warning)
	}

	fellBack := observed.FilterMessage("pipeline: detector fell back").All()
	if len(fellBack) != 1 {
		t.Fatalf("expected exactly one fell-back warn log, got %d", len(fellBack))
	}
	if fellBack[0].Level != zapcore.WarnLevel {
		t.Fatalf("expected warn level, got %v", fellBack[0].Level)
	}
	fields := fellBack[0].ContextMap()
	if fields["detector"] != "maven-detector" || fields["fallback_detector"] != "syft-detector" {
		t.Fatalf("unexpected log fields %#v", fields)
	}
	if reason, _ := fields["reason"].(string); !strings.Contains(reason, "java executable not found on PATH") {
		t.Fatalf("expected ready reason in log, got %#v", fields["reason"])
	}
}

func TestPipeline_RunAttributesFallbackWarningToSubproject(t *testing.T) {
	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "go-native", SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
		err:        errors.New("go not installed"),
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "syft-detector", SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackTestGraph(t), sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	result, err := pipeline.Run(context.Background(), PipelineRequest{
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo/services/api"},
			RelativePath:            "services/api",
			PrimaryDetector:         "go-native",
			DetectedPackageManagers: []PackageManager{PackageManagerGoMod},
			Ecosystem:               EcosystemGo,
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.DetectorWarnings) != 1 {
		t.Fatalf("expected one detector warning, got %#v", result.DetectorWarnings)
	}
	// Location lives in the warning's fields, not in the message text, so
	// grouping and deduplication stay message-based.
	warning := result.DetectorWarnings[0]
	if warning.Subproject != "services/api" {
		t.Fatalf("expected the subproject on the warning, got %+v", warning)
	}
	if warning.Manifest != "go.mod" {
		t.Fatalf("expected the manifest on the warning, got %+v", warning)
	}
}

func TestPipeline_RunNoWarningForNotApplicableFallback(t *testing.T) {
	registry := newTestRegistry()
	notApplicable := false
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-lockfile", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		applicable: &notApplicable,
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-native", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackTestGraph(t), sdk.ManifestMetadata{Path: "package.json", Kind: "package.json"})},
	})

	core, observed := observer.New(zapcore.WarnLevel)
	pipeline := NewPipeline(registry, zap.New(core))
	result, err := pipeline.Run(context.Background(), PipelineRequest{
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
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
	if len(result.DetectorWarnings) != 0 {
		t.Fatalf("expected no detector warnings, got %#v", result.DetectorWarnings)
	}
	if logs := observed.All(); len(logs) != 0 {
		t.Fatalf("expected no warn logs, got %#v", logs)
	}
}

func TestPipeline_EmitsStageInfoLogs(t *testing.T) {
	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(fallbackTestGraph(t), sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})

	core, observed := observer.New(zapcore.InfoLevel)
	pipeline := NewPipeline(registry, zap.New(core))
	if _, err := pipeline.Run(context.Background(), PipelineRequest{
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
		Subprojects: []Subproject{{
			ExecutionTarget:         ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
		MatchEnabled: true,
		AuditEnabled: true,
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	for _, message := range []string{
		"pipeline: detection started",
		"pipeline: detection completed",
		"pipeline: consolidation completed",
		"pipeline: enrichment started",
		"pipeline: enrichment completed",
		"pipeline: policy evaluation started",
		"pipeline: policy evaluation completed",
	} {
		if len(observed.FilterMessage(message).All()) != 1 {
			t.Errorf("expected exactly one %q info log", message)
		}
	}

	completed := observed.FilterMessage("pipeline: detection completed").All()[0].ContextMap()
	if completed["subprojects"] != int64(1) || completed["succeeded"] != int64(1) || completed["failed"] != int64(0) {
		t.Fatalf("unexpected detection completion fields %#v", completed)
	}
	if completed["packages"] != int64(1) {
		t.Fatalf("expected package count in detection completion, got %#v", completed["packages"])
	}
}
