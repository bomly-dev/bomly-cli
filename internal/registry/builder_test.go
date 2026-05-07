package registry

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func TestBuildScanRegistryRegistersDetectorForEveryPackageManager(t *testing.T) {
	builtins := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	builtins.Build()

	for _, packageManager := range SupportedPackageManagers() {
		detectorChain := builtins.Detectors(sdk.DetectionRequest{
			Ecosystem:      packageManager.Ecosystem(),
			PackageManager: packageManager,
			Mode:           sdk.TargetModeFullGraph,
		})
		if len(detectorChain) == 0 {
			t.Fatalf("expected detectors for package manager %q", packageManager.Name())
		}
	}
}

func TestBuildScanRegistryUsesSyftForUnclaimedManagers(t *testing.T) {
	builtins := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	builtins.Build()

	detectorChain := builtins.Detectors(sdk.DetectionRequest{
		Ecosystem:      sdk.PackageManagerTerraform.Ecosystem(),
		PackageManager: sdk.PackageManagerTerraform,
		Mode:           sdk.TargetModeFullGraph,
	})
	if len(detectorChain) != 1 {
		t.Fatalf("expected a single detector for %q, got %d", sdk.PackageManagerTerraform.Name(), len(detectorChain))
	}
	if got := detectorChain[0].Descriptor().Name; got != "syft-detector" {
		t.Fatalf("expected syft detector for %q, got %q", sdk.PackageManagerTerraform.Name(), got)
	}
}

func TestBuildScanRegistryKeepsNativeDetectorFirstForNativeManagers(t *testing.T) {
	builtins := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	builtins.Build()

	testCases := []struct {
		manager      sdk.PackageManager
		detectorName string
	}{
		{manager: sdk.PackageManagerNPM, detectorName: "npm-detector"},
		{manager: sdk.PackageManagerComposer, detectorName: "composer-detector"},
		{manager: sdk.PackageManagerBundler, detectorName: "bundler-detector"},
		{manager: sdk.PackageManagerGitHubActions, detectorName: "github-actions-detector"},
		{manager: sdk.PackageManagerNuGet, detectorName: "nuget-detector"},
		{manager: sdk.PackageManagerCargo, detectorName: "cargo-detector"},
		{manager: sdk.PackageManagerPub, detectorName: "pub-detector"},
		{manager: sdk.PackageManagerCocoaPods, detectorName: "cocoapods-detector"},
		{manager: sdk.PackageManagerSwiftPM, detectorName: "swiftpm-detector"},
		{manager: sdk.PackageManagerMix, detectorName: "mix-detector"},
		{manager: sdk.PackageManagerConan, detectorName: "conan-detector"},
		{manager: sdk.PackageManagerSBT, detectorName: "sbt-detector"},
	}

	for _, tc := range testCases {
		detectorChain := builtins.Detectors(sdk.DetectionRequest{
			Ecosystem:      tc.manager.Ecosystem(),
			PackageManager: tc.manager,
			Mode:           sdk.TargetModeFullGraph,
		})
		if len(detectorChain) == 0 {
			t.Fatalf("expected at least one detector for %q", tc.manager.Name())
		}
		if got := detectorChain[0].Descriptor().Name; got != tc.detectorName {
			t.Fatalf("expected native detector first for %q, got %q", tc.manager.Name(), got)
		}
	}
}

func TestBuildScanRegistryRegistersContainerDiscoveryPlanForSyft(t *testing.T) {
	builtins := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	builtins.Build()

	plan, ok := builtins.DiscoveryPlans()["syft-detector"]
	if !ok {
		t.Fatal("expected syft discovery plan to be registered")
	}
	if len(plan.TargetKinds) != 1 || plan.TargetKinds[0] != sdk.ExecutionTargetContainerImage {
		t.Fatalf("expected syft container discovery plan, got %#v", plan.TargetKinds)
	}
}

func TestBuildScanRegistryRegistersBuiltInMatchers(t *testing.T) {
	builtins := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	builtins.Build()

	got := make(map[string]sdk.DetectorOrigin)
	for _, descriptor := range builtins.MatcherDescriptors() {
		got[descriptor.Name] = descriptor.Origin
	}

	// grype is a bundled third-party library; it keeps BundledOrigin.
	for _, name := range []string{"grype"} {
		origin, ok := got[name]
		if !ok {
			t.Fatalf("expected built-in matcher %q to be registered; got %#v", name, got)
		}
		if origin != sdk.BundledOrigin {
			t.Fatalf("expected matcher %q to be bundled origin, got %q", name, origin)
		}
	}

	// Core matchers are implemented directly in Bomly's codebase; they use CoreOrigin.
	for _, name := range []string{"osv", "depsdev-license-checker", "clearlydefined-license-checker", "eol-checker"} {
		origin, ok := got[name]
		if !ok {
			t.Fatalf("expected built-in matcher %q to be registered; got %#v", name, got)
		}
		if origin != sdk.CoreOrigin {
			t.Fatalf("expected matcher %q to be core origin, got %q", name, origin)
		}
	}
}
