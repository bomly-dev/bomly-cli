package registry

import (
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func TestBuildScanRegistryRegistersDetectorForEveryPackageManager(t *testing.T) {
	builtins := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	builtins.Build()

	for _, packageManager := range SupportedPackageManagers() {
		detectorChain := builtins.Detectors(model.DetectionRequest{
			Ecosystem:      packageManager.Ecosystem(),
			PackageManager: packageManager,
			Mode:           model.TargetModeFullGraph,
		})
		if len(detectorChain) == 0 {
			t.Fatalf("expected detectors for package manager %q", packageManager.Name())
		}
	}
}

func TestBuildScanRegistryUsesSyftForUnclaimedManagers(t *testing.T) {
	builtins := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	builtins.Build()

	detectorChain := builtins.Detectors(model.DetectionRequest{
		Ecosystem:      model.PackageManagerTerraform.Ecosystem(),
		PackageManager: model.PackageManagerTerraform,
		Mode:           model.TargetModeFullGraph,
	})
	if len(detectorChain) != 1 {
		t.Fatalf("expected a single detector for %q, got %d", model.PackageManagerTerraform.Name(), len(detectorChain))
	}
	if got := detectorChain[0].Descriptor().Name; got != "syft-detector" {
		t.Fatalf("expected syft detector for %q, got %q", model.PackageManagerTerraform.Name(), got)
	}
}

func TestBuildScanRegistryKeepsNativeDetectorFirstForNativeManagers(t *testing.T) {
	builtins := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	builtins.Build()

	testCases := []struct {
		manager      model.PackageManager
		detectorName string
	}{
		{manager: model.PackageManagerNPM, detectorName: "npm-detector"},
		{manager: model.PackageManagerComposer, detectorName: "composer-detector"},
		{manager: model.PackageManagerBundler, detectorName: "bundler-detector"},
		{manager: model.PackageManagerGitHubActions, detectorName: "github-actions-detector"},
		{manager: model.PackageManagerNuGet, detectorName: "nuget-detector"},
		{manager: model.PackageManagerCargo, detectorName: "cargo-detector"},
		{manager: model.PackageManagerPub, detectorName: "pub-detector"},
		{manager: model.PackageManagerCocoaPods, detectorName: "cocoapods-detector"},
		{manager: model.PackageManagerSwiftPM, detectorName: "swiftpm-detector"},
		{manager: model.PackageManagerMix, detectorName: "mix-detector"},
		{manager: model.PackageManagerConan, detectorName: "conan-detector"},
		{manager: model.PackageManagerSBT, detectorName: "sbt-detector"},
	}

	for _, tc := range testCases {
		detectorChain := builtins.Detectors(model.DetectionRequest{
			Ecosystem:      tc.manager.Ecosystem(),
			PackageManager: tc.manager,
			Mode:           model.TargetModeFullGraph,
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
	if len(plan.TargetKinds) != 1 || plan.TargetKinds[0] != model.ExecutionTargetContainerImage {
		t.Fatalf("expected syft container discovery plan, got %#v", plan.TargetKinds)
	}
}

func TestBuildScanRegistryRegistersBuiltInMatchers(t *testing.T) {
	builtins := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	builtins.Build()

	got := make(map[string]model.DetectorOrigin)
	for _, descriptor := range builtins.MatcherDescriptors() {
		got[descriptor.Name] = descriptor.Origin
	}

	// grype is a bundled third-party library; it keeps BundledOrigin.
	for _, name := range []string{"grype"} {
		origin, ok := got[name]
		if !ok {
			t.Fatalf("expected built-in matcher %q to be registered; got %#v", name, got)
		}
		if origin != model.BundledOrigin {
			t.Fatalf("expected matcher %q to be bundled origin, got %q", name, origin)
		}
	}

	// Core matchers are implemented directly in Bomly's codebase; they use CoreOrigin.
	for _, name := range []string{"osv", "depsdev-license-checker", "clearlydefined-license-checker", "eol-checker"} {
		origin, ok := got[name]
		if !ok {
			t.Fatalf("expected built-in matcher %q to be registered; got %#v", name, got)
		}
		if origin != model.CoreOrigin {
			t.Fatalf("expected matcher %q to be core origin, got %q", name, origin)
		}
	}
}
