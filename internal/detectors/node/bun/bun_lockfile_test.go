package bun

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestLockfileDetectorUsesSyftFallbackForBinaryLockfile(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "bun.lockb"), []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	detector := LockfileDetector{}
	applicable, err := detector.Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: project})
	if err != nil || !applicable {
		t.Fatalf("expected binary lockfile to be applicable: applicable=%v err=%v", applicable, err)
	}
	_, err = detector.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: project})
	if err == nil || !strings.Contains(err.Error(), "Syft fallback") || !strings.Contains(err.Error(), "--save-text-lockfile") {
		t.Fatalf("expected actionable fallback error, got %v", err)
	}
}

func TestLockfileDetectorDescriptor(t *testing.T) {
	descriptor := (LockfileDetector{}).Descriptor()
	if len(descriptor.SupportedManagers) != 1 || descriptor.SupportedManagers[0] != sdk.PackageManagerBun {
		t.Fatalf("unexpected supported managers: %#v", descriptor.SupportedManagers)
	}
	support := (LockfileDetector{}).PackageManagerSupport()
	if len(support) != 1 || len(support[0].EvidencePatterns) != 2 {
		t.Fatalf("unexpected Bun support metadata: %#v", support)
	}
}
