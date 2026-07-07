package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestResolveDetector_InjectsRequestScopedLogger verifies the pipeline binds a
// subproject/detector-scoped logger onto the request so a detector instance
// shared across concurrently-resolved subprojects can attribute its output.
func TestResolveDetector_InjectsRequestScopedLogger(t *testing.T) {
	registry := newTestRegistry()
	graph := sdk.New()
	if err := graph.AddNode(sdk.NewDependencyRef("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}

	var seen *zap.Logger
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-native", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
		onResolve: func(req ResolveGraphRequest) {
			seen = req.Logger
		},
	})

	pipeline := NewPipeline(registry, zap.NewNop())
	req := ResolveGraphRequest{
		Ecosystem:      EcosystemNPM,
		PackageManager: PackageManagerNPM,
		Subproject: Subproject{
			ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo/services/api"},
			RelativePath:    "services/api",
			Ecosystem:       EcosystemNPM,
		},
	}
	if _, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil); err != nil {
		t.Fatalf("resolveDetectors() error = %v", err)
	}
	if seen == nil {
		t.Fatal("expected a request-scoped logger to be injected, got nil")
	}
	// DetectorLogger must never return nil and must prefer the injected logger.
	if got := req.DetectorLogger(nil); got == nil {
		t.Fatal("DetectorLogger(nil) returned nil")
	}
}

// TestResolveDetector_FallbackLoggerRelabelled verifies each detector in a
// fallback chain gets a logger bound to its own name and subproject, so a
// fallback's log lines are not misattributed to the primary detector.
func TestResolveDetector_FallbackLoggerRelabelled(t *testing.T) {
	registry := newTestRegistry()
	graph := sdk.New()
	if err := graph.AddNode(sdk.NewDependencyRef("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}

	logDetector := func(name string) func(ResolveGraphRequest) {
		return func(req ResolveGraphRequest) {
			req.Logger.Info("resolving")
		}
	}
	registry.registerDetector(fakeFallbackDetector{
		fakeDetector: fakeDetector{
			descriptor: DetectorDescriptor{Name: "go-native", SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
			err:        errors.New("go not installed"),
			onResolve:  logDetector("go-native"),
		},
		fallback: fakeDetector{
			descriptor: DetectorDescriptor{Name: "syft-detector", SupportedEcosystems: []Ecosystem{EcosystemGo}, SupportedManagers: []PackageManager{PackageManagerGoMod}},
			result:     ResolveGraphResult{Graphs: SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"})},
			onResolve:  logDetector("syft-detector"),
		},
	})

	core, logs := observer.New(zapcore.InfoLevel)
	pipeline := NewPipeline(registry, zap.New(core))
	req := ResolveGraphRequest{
		Ecosystem:      EcosystemGo,
		PackageManager: PackageManagerGoMod,
		Subproject: Subproject{
			ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo/svc"},
			RelativePath:    "svc",
			Ecosystem:       EcosystemGo,
		},
	}
	if _, err := pipeline.resolveDetectors(context.Background(), req, registry.Detectors(req), nil); err != nil {
		t.Fatalf("resolveDetectors() error = %v", err)
	}

	detectorsByEntry := map[string]string{}
	for _, entry := range logs.All() {
		if entry.Message != "resolving" {
			continue
		}
		if entry.LoggerName != "svc" {
			t.Fatalf("expected logger name %q, got %q", "svc", entry.LoggerName)
		}
		for _, f := range entry.Context {
			if f.Key == "detector" {
				detectorsByEntry[f.String] = entry.LoggerName
			}
		}
	}
	if _, ok := detectorsByEntry["go-native"]; !ok {
		t.Fatalf("expected a log line attributed to go-native, got %v", detectorsByEntry)
	}
	if _, ok := detectorsByEntry["syft-detector"]; !ok {
		t.Fatalf("expected a log line attributed to syft-detector, got %v", detectorsByEntry)
	}
}

// TestDetectorLoggerFallback documents the resolution order without a pipeline.
func TestDetectorLoggerFallback(t *testing.T) {
	fallback := zap.NewNop()
	if got := (sdk.DetectionRequest{}).DetectorLogger(fallback); got != fallback {
		t.Fatal("expected fallback logger when request logger is unset")
	}
	scoped := zap.NewNop().Named("scoped")
	if got := (sdk.DetectionRequest{Logger: scoped}).DetectorLogger(fallback); got != scoped {
		t.Fatal("expected request-scoped logger to take precedence over fallback")
	}
	if got := (sdk.DetectionRequest{}).DetectorLogger(nil); got == nil {
		t.Fatal("expected a no-op logger, got nil")
	}
}
