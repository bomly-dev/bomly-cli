package opts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// probeErrorFor runs discovery against root with the supplied request tweaks
// and returns the "no subprojects discovered" error text.
func probeErrorFor(t *testing.T, root string, mutate func(*Request)) string {
	t.Helper()
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()

	req := Request{
		Registry:        reg,
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root},
	}
	if mutate != nil {
		mutate(&req)
	}

	_, err := PlanSubprojects(reg, req)
	if !errors.Is(err, ErrNoSubprojects) {
		t.Fatalf("expected ErrNoSubprojects, got %v", err)
	}
	return err.Error()
}

func TestDiscoveryProbeExplainsEcosystemIncludeSkip(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "package.json")

	msg := probeErrorFor(t, root, func(req *Request) {
		req.EcosystemFilter = sdk.EcosystemFilter{Include: []sdk.Ecosystem{sdk.EcosystemGo}}
	})
	want := fmt.Sprintf("skipped: excluded by --ecosystems %s", sdk.EcosystemGo)
	if !strings.Contains(msg, want) {
		t.Fatalf("expected %q in error, got %q", want, msg)
	}
}

func TestDiscoveryProbeExplainsEcosystemExcludeSkip(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "package.json")

	ecosystem := sdk.PackageManagerNPM.Ecosystem()
	msg := probeErrorFor(t, root, func(req *Request) {
		req.EcosystemFilter = sdk.EcosystemFilter{Exclude: []sdk.Ecosystem{ecosystem}}
	})
	want := fmt.Sprintf("skipped: excluded by --ecosystems -%s", ecosystem)
	if !strings.Contains(msg, want) {
		t.Fatalf("expected %q in error, got %q", want, msg)
	}
}

func TestDiscoveryProbeExplainsDetectorFilterSkip(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "package.json")

	msg := probeErrorFor(t, root, func(req *Request) {
		req.DetectorFilter = sdk.DetectorFilter{Include: []string{"gomod"}}
	})
	want := fmt.Sprintf("skipped: detector filter excludes every %s detector", sdk.PackageManagerNPM.Name())
	if !strings.Contains(msg, want) {
		t.Fatalf("expected %q in error, got %q", want, msg)
	}
}

func TestDiscoveryProbeExplainsNonRecursiveSkip(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "web/package.json")

	msg := probeErrorFor(t, root, nil)
	if !strings.Contains(msg, "package.json at web (npm) — skipped: not scanned without --recursive") {
		t.Fatalf("expected nested candidate skip reason, got %q", msg)
	}
}

func TestDiscoveryProbeExplainsExcludeGlobSkip(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "web/nested/package.json")

	msg := probeErrorFor(t, root, func(req *Request) {
		req.Recursive = true
		req.MaxDepth = 3
		req.ExcludeGlobs = []string{"web"}
	})
	// The exclude prunes the whole subtree, so a candidate below the excluded
	// directory must be attributed to the pattern that pruned its ancestor.
	if !strings.Contains(msg, "skipped: excluded by --exclude web") {
		t.Fatalf("expected exclude-glob skip reason, got %q", msg)
	}
}

func TestDiscoveryProbeExplainsMaxDepthSkip(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "a/b/package.json")

	msg := probeErrorFor(t, root, func(req *Request) {
		req.Recursive = true
		req.MaxDepth = 1
	})
	if !strings.Contains(msg, "skipped: below --max-depth 1") {
		t.Fatalf("expected max-depth skip reason, got %q", msg)
	}
}

// notReadyDetector reports a fixed readiness failure, standing in for a
// detector whose toolchain is missing from PATH.
type notReadyDetector struct {
	name string
	err  error
}

func (d notReadyDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{Name: d.name}
}
func (d notReadyDetector) PackageManagerSupport() []sdk.PackageManagerSupport { return nil }
func (d notReadyDetector) Ready(context.Context, sdk.DetectionRequest) error  { return d.err }
func (d notReadyDetector) Applicable(context.Context, sdk.DetectionRequest) (bool, error) {
	return true, nil
}
func (d notReadyDetector) ResolveGraph(context.Context, sdk.DetectionRequest) (sdk.DetectionResult, error) {
	return sdk.DetectionResult{}, nil
}

func TestReadinessSkipReasonNamesEveryUnusableChainLink(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	reg.RegisterDetector(notReadyDetector{name: "fake-npm-native", err: errors.New("npm not on PATH")})
	reg.RegisterDetector(notReadyDetector{name: "fake-npm", err: errors.New("no committed lockfile")})

	diagnostics := newDiscoveryDiagnostics(reg, Request{Registry: reg})
	defer diagnostics.close()

	subproject := sdk.Subproject{
		ExecutionTarget:  sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: t.TempDir()},
		RelativePath:     ".",
		PlannedDetectors: []string{"fake-npm-native", "fake-npm"},
	}
	got := diagnostics.readinessSkipReason(subproject, sdk.PackageManagerNPM)
	want := "fake-npm-native not ready (npm not on PATH); fake-npm not ready (no committed lockfile)"
	if got != want {
		t.Fatalf("readinessSkipReason() = %q, want %q", got, want)
	}
}

func TestReadinessSkipReasonStaysSilentWhenAnyDetectorIsReady(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	reg.RegisterDetector(notReadyDetector{name: "fake-npm-native", err: errors.New("npm not on PATH")})
	reg.RegisterDetector(notReadyDetector{name: "fake-npm"})

	diagnostics := newDiscoveryDiagnostics(reg, Request{Registry: reg})
	defer diagnostics.close()

	subproject := sdk.Subproject{
		ExecutionTarget:  sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: t.TempDir()},
		RelativePath:     ".",
		PlannedDetectors: []string{"fake-npm-native", "fake-npm"},
	}
	if got := diagnostics.readinessSkipReason(subproject, sdk.PackageManagerNPM); got != "" {
		t.Fatalf("expected no reason when a fallback is ready, got %q", got)
	}
}

func TestDescribeDiscoveryOmitsSkipReasons(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "web/package.json")

	lines := DescribeDiscovery(sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "package.json at web") {
		t.Fatalf("expected probe evidence, got %q", joined)
	}
	// DescribeDiscovery has no request context to replay, so it must not
	// speculate about skip reasons.
	if strings.Contains(joined, "skipped:") {
		t.Fatalf("expected no skip reasons without request context, got %q", joined)
	}
}
