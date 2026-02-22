package registry

import (
	"testing"

	"github.com/bomly/bomly-cli/internal/scan"
	"go.uber.org/zap"
)

func TestBuildScanRegistryRegistersDetectorForEveryPackageManager(t *testing.T) {
	builtins := BuildScanRegistry(zap.NewNop(), Config{})

	for _, packageManager := range SupportedPackageManagers() {
		detectors := builtins.Detectors(scan.ResolveGraphRequest{
			Ecosystem:      packageManager.Ecosystem(),
			PackageManager: packageManager,
			Mode:           scan.TargetModeFullGraph,
		})
		if len(detectors) == 0 {
			t.Fatalf("expected detectors for package manager %q", packageManager.Name())
		}
	}
}

func TestBuildScanRegistryUsesSyftForSyftOnlyManagers(t *testing.T) {
	builtins := BuildScanRegistry(zap.NewNop(), Config{})

	detectors := builtins.Detectors(scan.ResolveGraphRequest{
		Ecosystem:      PackageManagerCargo.Ecosystem(),
		PackageManager: PackageManagerCargo,
		Mode:           scan.TargetModeFullGraph,
	})
	if len(detectors) != 1 {
		t.Fatalf("expected a single detector for %q, got %d", PackageManagerCargo.Name(), len(detectors))
	}
	if got := detectors[0].Descriptor().Name; got != "syft-detector" {
		t.Fatalf("expected syft detector for %q, got %q", PackageManagerCargo.Name(), got)
	}
}

func TestBuildScanRegistryKeepsNativeDetectorFirstForNativeManagers(t *testing.T) {
	builtins := BuildScanRegistry(zap.NewNop(), Config{})

	testCases := []struct {
		manager      PackageManager
		detectorName string
	}{
		{manager: PackageManagerNPM, detectorName: "npm-detector"},
		{manager: PackageManagerComposer, detectorName: "composer-detector"},
		{manager: PackageManagerBundler, detectorName: "bundler-detector"},
		{manager: PackageManagerGitHubActions, detectorName: "github-actions-detector"},
	}

	for _, tc := range testCases {
		detectors := builtins.Detectors(scan.ResolveGraphRequest{
			Ecosystem:      tc.manager.Ecosystem(),
			PackageManager: tc.manager,
			Mode:           scan.TargetModeFullGraph,
		})
		if len(detectors) == 0 {
			t.Fatalf("expected at least one detector for %q", tc.manager.Name())
		}
		if got := detectors[0].Descriptor().Name; got != tc.detectorName {
			t.Fatalf("expected native detector first for %q, got %q", tc.manager.Name(), got)
		}
	}
}

func TestBuildScanRegistryRegistersContainerDiscoveryPlanForSyft(t *testing.T) {
	builtins := BuildScanRegistry(zap.NewNop(), Config{})

	plan, ok := builtins.DiscoveryPlans()["syft-detector"]
	if !ok {
		t.Fatal("expected syft discovery plan to be registered")
	}
	if len(plan.TargetKinds) != 1 || plan.TargetKinds[0] != scan.ExecutionTargetContainerImage {
		t.Fatalf("expected syft container discovery plan, got %#v", plan.TargetKinds)
	}
}
