package opts

import (
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
	// One shared reason is stated once in the section header, not repeated on
	// every candidate line.
	if !strings.Contains(msg, "all skipped: not scanned without --recursive") {
		t.Fatalf("expected hoisted skip reason, got %q", msg)
	}
	if !strings.Contains(msg, "- web/package.json (npm)") {
		t.Fatalf("expected candidate line, got %q", msg)
	}
}

func TestDiscoveryProbeKeepsPerCandidateReasonsWhenTheyDiffer(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "go.mod")
	writeEvidenceFile(t, root, "web/package.json")

	msg := probeErrorFor(t, root, func(req *Request) {
		req.EcosystemFilter = sdk.EcosystemFilter{Exclude: []sdk.Ecosystem{sdk.EcosystemGo}}
	})
	if strings.Contains(msg, "all skipped:") {
		t.Fatalf("expected per-candidate reasons when they differ, got %q", msg)
	}
	if !strings.Contains(msg, fmt.Sprintf("- go.mod (gomod) — skipped: excluded by --ecosystems -%s", sdk.EcosystemGo)) {
		t.Fatalf("expected ecosystem reason on the root candidate, got %q", msg)
	}
	if !strings.Contains(msg, "- web/package.json (npm) — skipped: not scanned without --recursive") {
		t.Fatalf("expected recursion reason on the nested candidate, got %q", msg)
	}
}

func TestNoSubprojectsErrorReportsWhatWasSearched(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "web/package.json")

	msg := probeErrorFor(t, root, func(req *Request) {
		req.Recursive = true
		req.MaxDepth = 2
		req.ExcludeGlobs = []string{"web"}
		req.DetectorFilter = sdk.DetectorFilter{Include: []string{"gomod"}}
	})
	for _, want := range []string{
		"\n  target: " + root,
		"\n  search: recursive discovery, max depth 2, 1 exclude pattern(s)",
		"\n  active filters: --detectors gomod",
		"\n  manifest candidates found (depth <= 3)",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("expected %q in report, got %q", want, msg)
		}
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

func TestDescribeDiscoveryOmitsSkipReasons(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "web/package.json")

	lines := DescribeDiscovery(sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "web/package.json (npm)") {
		t.Fatalf("expected probe evidence, got %q", joined)
	}
	// DescribeDiscovery has no request context to replay, so it must not
	// speculate about skip reasons.
	if strings.Contains(joined, "skipped:") {
		t.Fatalf("expected no skip reasons without request context, got %q", joined)
	}
}
