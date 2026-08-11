package registry

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestBuildScanRegistryRegistersDetectorForEveryPackageManager(t *testing.T) {
	builtins := NewRegistry(Configs{}, *zap.NewNop())
	builtins.Build()

	for _, packageManager := range SupportedPackageManagers() {
		detectorChain := builtins.Detectors(sdk.DetectionRequest{
			Ecosystem:      packageManager.Ecosystem(),
			PackageManager: packageManager,
		})
		if len(detectorChain) == 0 {
			t.Fatalf("expected detectors for package manager %q", packageManager.Name())
		}
	}
}

func TestBuildScanRegistryUsesSyftForUnclaimedManagers(t *testing.T) {
	builtins := NewRegistry(Configs{}, *zap.NewNop())
	builtins.Build()

	detectorChain := builtins.Detectors(sdk.DetectionRequest{
		Ecosystem:      sdk.PackageManagerTerraform.Ecosystem(),
		PackageManager: sdk.PackageManagerTerraform,
	})
	if len(detectorChain) != 1 {
		t.Fatalf("expected a single detector for %q, got %d", sdk.PackageManagerTerraform.Name(), len(detectorChain))
	}
	if got := detectorChain[0].Descriptor().Name; got != "syft-detector" {
		t.Fatalf("expected syft detector for %q, got %q", sdk.PackageManagerTerraform.Name(), got)
	}
}

func TestBuildScanRegistryKeepsNativeDetectorFirstForNativeManagers(t *testing.T) {
	builtins := NewRegistry(Configs{}, *zap.NewNop())
	builtins.Build()

	testCases := []struct {
		manager      sdk.PackageManager
		detectorName string
	}{
		{manager: sdk.PackageManagerNPM, detectorName: "npm"},
		{manager: sdk.PackageManagerComposer, detectorName: "composer-detector"},
		{manager: sdk.PackageManagerBundler, detectorName: "bundler-detector"},
		{manager: sdk.PackageManagerGitHubActions, detectorName: "github-actions-detector"},
		{manager: sdk.PackageManagerNuGet, detectorName: "nuget-detector"},
		{manager: sdk.PackageManagerCargo, detectorName: "cargo-detector"},
		{manager: sdk.PackageManagerPub, detectorName: "pub-native-detector"},
		{manager: sdk.PackageManagerCocoaPods, detectorName: "cocoapods-detector"},
		{manager: sdk.PackageManagerSwiftPM, detectorName: "swiftpm-native-detector"},
		{manager: sdk.PackageManagerMix, detectorName: "mix-detector"},
		{manager: sdk.PackageManagerConan, detectorName: "conan-detector"},
		{manager: sdk.PackageManagerSBT, detectorName: "sbt-native-detector"},
	}

	for _, tc := range testCases {
		detectorChain := builtins.Detectors(sdk.DetectionRequest{
			Ecosystem:      tc.manager.Ecosystem(),
			PackageManager: tc.manager,
		})
		if len(detectorChain) == 0 {
			t.Fatalf("expected at least one detector for %q", tc.manager.Name())
		}
		if got := detectorChain[0].Descriptor().Name; got != tc.detectorName {
			t.Fatalf("expected native detector first for %q, got %q", tc.manager.Name(), got)
		}
	}
}

func TestBuildScanRegistryAdvertisesBuiltInRemediationCapabilities(t *testing.T) {
	builtins := NewRegistry(Configs{}, *zap.NewNop())
	builtins.Build()

	detectors := builtins.Detectors(sdk.DetectionRequest{
		Ecosystem:      sdk.EcosystemNPM,
		PackageManager: sdk.PackageManagerNPM,
	})
	if len(detectors) == 0 {
		t.Fatal("expected npm detector")
	}
	capabilities := detectors[0].Descriptor().RemediationCapabilities
	if len(capabilities) == 0 {
		t.Fatal("npm detector did not advertise remediation capabilities")
	}
	if !slices.Contains(capabilities[0].Actions, sdk.RemediationActionDirectBump) ||
		!slices.Contains(capabilities[0].Actions, sdk.RemediationActionTransitiveOverride) {
		t.Fatalf("npm remediation capabilities = %#v", capabilities)
	}
	capabilities[0].Actions[0] = sdk.RemediationActionLockfileRefresh
	fresh := detectors[0].Descriptor().RemediationCapabilities
	if len(fresh) == 0 || fresh[0].Actions[0] == sdk.RemediationActionLockfileRefresh {
		t.Fatalf("detector descriptor shared remediation capability slices: %#v", fresh)
	}
}

func TestBuildScanRegistryRegistersContainerDiscoveryPlanForSyft(t *testing.T) {
	builtins := NewRegistry(Configs{}, *zap.NewNop())
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
	builtins := NewRegistry(Configs{}, *zap.NewNop())
	builtins.Build()

	got := make(map[string]struct{})
	for _, descriptor := range builtins.MatcherDescriptors() {
		got[descriptor.Name] = struct{}{}
	}

	for _, name := range []string{"grype", "osv", "depsdev-license-matcher", "scorecard"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("expected built-in matcher %q to be registered; got %#v", name, got)
		}
	}
	defaults := builtins.DefaultEnabledMatcherNames()
	for _, name := range []string{"grype", "depsdev-license-matcher"} {
		if !slices.Contains(defaults, name) {
			t.Fatalf("expected matcher %q to be enabled by default; got %#v", name, defaults)
		}
	}
	for _, name := range []string{"osv", "scorecard"} {
		if slices.Contains(defaults, name) {
			t.Fatalf("expected matcher %q to be opt-in; got %#v", name, defaults)
		}
	}
}

func TestRegistryHTTPClientProviderReusesTransport(t *testing.T) {
	builtins := NewRegistry(Configs{HTTPProxy: "http://proxy.example:8080"}, *zap.NewNop())

	provider := builtins.httpClientProvider()
	first := provider.Client(15 * time.Second)
	second := provider.Client(30 * time.Second)
	if first.Transport != second.Transport {
		t.Fatalf("registry clients do not share transport")
	}
	if first.Timeout != 15*time.Second || second.Timeout != 30*time.Second {
		t.Fatalf("timeouts = %v/%v, want 15s/30s", first.Timeout, second.Timeout)
	}
}

func TestRegisterScorecardMatcherDoesNotLogEndpointCredentials(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	builtins := NewRegistry(Configs{
		ScorecardAPIBase: "https://agent:super-secret@scorecard.example/api",
	}, *zap.New(core))

	builtins.registerCompositionEntries(sdk.PluginKindMatcher)

	entries := logs.FilterMessage("scorecard matcher configured").All()
	if len(entries) != 1 {
		t.Fatalf("scorecard configuration logs = %d, want 1", len(entries))
	}
	apiBase, ok := entries[0].ContextMap()["api_base"].(string)
	if !ok {
		t.Fatalf("api_base log field = %#v, want string", entries[0].ContextMap()["api_base"])
	}
	if apiBase != "https://scorecard.example/api" {
		t.Fatalf("api_base log field = %q, want URL without credentials", apiBase)
	}
	if strings.Contains(apiBase, "agent") || strings.Contains(apiBase, "super-secret") {
		t.Fatalf("api_base log field leaked credentials: %q", apiBase)
	}
}

func TestComponentOriginRecordsAllKinds(t *testing.T) {
	builtins := NewRegistry(Configs{}, *zap.NewNop())
	builtins.Build()

	if origin := builtins.ComponentOrigin(sdk.PluginKindDetector, "go.mod"); origin != sdk.CoreOrigin {
		t.Fatalf("go.mod detector origin = %q, want core", origin)
	}
	if origin := builtins.DetectorOrigin("syft-detector"); origin != sdk.BundledOrigin {
		t.Fatalf("syft detector origin = %q, want bundled (via DetectorOrigin delegate)", origin)
	}
	if origin := builtins.ComponentOrigin(sdk.PluginKindAuditor, "license"); origin != sdk.CoreOrigin {
		t.Fatalf("license auditor origin = %q, want core", origin)
	}

	builtins.RegisterMatcherWithOptions(externalOriginMatcher{}, ComponentOptions{DefaultEnabled: true, Origin: sdk.ExternalOrigin})
	builtins.RegisterAnalyzerWithOptions(externalOriginAnalyzer{}, ComponentOptions{DefaultEnabled: true, Origin: sdk.ExternalOrigin})
	if origin := builtins.ComponentOrigin(sdk.PluginKindMatcher, "acme.matcher"); origin != sdk.ExternalOrigin {
		t.Fatalf("external matcher origin = %q, want external", origin)
	}
	if origin := builtins.ComponentOrigin(sdk.PluginKindAnalyzer, "acme.analyzer"); origin != sdk.ExternalOrigin {
		t.Fatalf("external analyzer origin = %q, want external", origin)
	}

	filtered := builtins.Filter(Filter{})
	if origin := filtered.ComponentOrigin(sdk.PluginKindMatcher, "acme.matcher"); origin != sdk.ExternalOrigin {
		t.Fatalf("filtered matcher origin = %q, want external", origin)
	}
}

type externalOriginMatcher struct{}

func (externalOriginMatcher) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{Name: "acme.matcher"}
}
func (externalOriginMatcher) Ready(context.Context, sdk.MatchRequest) error { return nil }
func (externalOriginMatcher) Applicable(context.Context, sdk.MatchRequest) (bool, error) {
	return true, nil
}
func (externalOriginMatcher) Match(_ context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	return sdk.MatchResult{Registry: req.Registry}, nil
}

type externalOriginAnalyzer struct{}

func (externalOriginAnalyzer) Descriptor() sdk.AnalyzerDescriptor {
	return sdk.AnalyzerDescriptor{Name: "acme.analyzer"}
}
func (externalOriginAnalyzer) Ready(context.Context, sdk.AnalyzeRequest) error { return nil }
func (externalOriginAnalyzer) Applicable(context.Context, sdk.AnalyzeRequest) (bool, error) {
	return true, nil
}
func (externalOriginAnalyzer) Analyze(_ context.Context, req sdk.AnalyzeRequest) (sdk.AnalyzeResult, error) {
	return sdk.AnalyzeResult{Registry: req.Registry}, nil
}
