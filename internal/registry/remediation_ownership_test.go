package registry

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func TestBuiltInDetectorsOwnRemediationCapabilitiesAndAdvice(t *testing.T) {
	testCases := []struct {
		name    string
		manager sdk.PackageManager
		action  sdk.RemediationAction
		advice  string
	}{
		{detectors.NameNPM, sdk.PackageManagerNPM, sdk.RemediationActionTransitiveOverride, `add "overrides": {"example": "1.2.0"} to package.json and run npm install`},
		{detectors.NameNPMNative, sdk.PackageManagerNPM, sdk.RemediationActionTransitiveOverride, `add "overrides": {"example": "1.2.0"} to package.json and run npm install`},
		{detectors.NamePNPM, sdk.PackageManagerPNPM, sdk.RemediationActionTransitiveOverride, `add "example": "1.2.0" under "pnpm"."overrides" in package.json (or under "overrides:" in pnpm-workspace.yaml for workspaces) and run pnpm install`},
		{detectors.NamePNPMNative, sdk.PackageManagerPNPM, sdk.RemediationActionTransitiveOverride, `add "example": "1.2.0" under "pnpm"."overrides" in package.json (or under "overrides:" in pnpm-workspace.yaml for workspaces) and run pnpm install`},
		{detectors.NameYarn, sdk.PackageManagerYarn, sdk.RemediationActionTransitiveOverride, `add "resolutions": {"example": "1.2.0"} to package.json and run yarn install`},
		{detectors.NameYarnNative, sdk.PackageManagerYarn, sdk.RemediationActionTransitiveOverride, `add "resolutions": {"example": "1.2.0"} to package.json and run yarn install`},
		{detectors.NameBun, sdk.PackageManagerBun, sdk.RemediationActionLockfileRefresh, "run bun update example@1.2.0"},
		{detectors.NameBunNative, sdk.PackageManagerBun, sdk.RemediationActionLockfileRefresh, "run bun update example@1.2.0"},
		{detectors.NameGoMod, sdk.PackageManagerGoMod, sdk.RemediationActionLockfileRefresh, "run go get example@v1.2.0 && go mod tidy"},
		{detectors.NameCargo, sdk.PackageManagerCargo, sdk.RemediationActionLockfileRefresh, "run cargo update -p example --precise 1.2.0"},
		{detectors.NameMaven, sdk.PackageManagerMaven, sdk.RemediationActionTransitiveOverride, "pin example to 1.2.0 in <dependencyManagement> of manifest.file"},
		{detectors.NameGradle, sdk.PackageManagerGradle, sdk.RemediationActionTransitiveOverride, `add dependencies { constraints { implementation("example:1.2.0") } } in manifest.file`},
		{detectors.NamePip, sdk.PackageManagerPip, sdk.RemediationActionTransitiveOverride, "add a constraint `example>=1.2.0` to your requirements or constraints file and reinstall"},
		{detectors.NamePipenv, sdk.PackageManagerPipenv, sdk.RemediationActionTransitiveOverride, "add a constraint `example>=1.2.0` to your requirements or constraints file and reinstall"},
		{detectors.NamePoetry, sdk.PackageManagerPoetry, sdk.RemediationActionTransitiveOverride, "pin `example>=1.2.0` in pyproject.toml and refresh the lockfile"},
		{detectors.NameUV, sdk.PackageManagerUV, sdk.RemediationActionTransitiveOverride, "pin `example>=1.2.0` in pyproject.toml and refresh the lockfile"},
		{detectors.NameBundler, sdk.PackageManagerBundler, sdk.RemediationActionTransitiveOverride, `add gem "example", ">= 1.2.0" to the Gemfile and run bundle update example`},
		{detectors.NameComposer, sdk.PackageManagerComposer, sdk.RemediationActionTransitiveOverride, `require "example": "^1.2.0" in manifest.file and run composer update example`},
	}

	builtIns := make(map[string]sdk.Detector)
	for _, detector := range BuiltinDetectors() {
		builtIns[detector.Descriptor().Name] = detector
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			detector, ok := builtIns[testCase.name]
			if !ok {
				t.Fatalf("built-in detector %q not found", testCase.name)
			}
			descriptor := detector.Descriptor()
			if len(descriptor.RemediationCapabilities) == 0 {
				t.Fatalf("%s does not advertise its remediation capability", testCase.name)
			}
			provider, ok := detector.(sdk.DetectorRemediationProvider)
			if !ok {
				t.Fatalf("%s advertises remediation without implementing the provider", testCase.name)
			}
			response, err := provider.RemediationHints(context.Background(), remediationHintRequest(t, testCase.manager))
			if err != nil {
				t.Fatalf("RemediationHints() error = %v", err)
			}
			if got := adviceForAction(response, testCase.action); got != testCase.advice {
				t.Fatalf("advice for %s = %q, want %q", testCase.action, got, testCase.advice)
			}
		})
	}
}

func TestRegistryDoesNotInferRemediationCapabilities(t *testing.T) {
	reg := NewRegistry(Configs{}, *zap.NewNop())
	reg.RegisterDetectorWithOptions(detectorWithoutRemediation{}, ComponentOptions{
		DefaultEnabled: true,
		Origin:         sdk.CoreOrigin,
	})

	descriptors := reg.DetectorDescriptors()
	if len(descriptors) != 1 {
		t.Fatalf("DetectorDescriptors() length = %d, want 1", len(descriptors))
	}
	if len(descriptors[0].RemediationCapabilities) != 0 {
		t.Fatalf("registry inferred remediation capabilities: %#v", descriptors[0].RemediationCapabilities)
	}
	if _, ok := reg.AllDetectors()[0].(sdk.DetectorRemediationProvider); ok {
		t.Fatal("registry added the remediation provider contract to an unsupported detector")
	}
}

func remediationHintRequest(t *testing.T, manager sdk.PackageManager) sdk.RemediationHintRequest {
	t.Helper()
	const packageRef = "pkg:generic/example@1.0.0"
	graph := sdk.New()
	dependency := sdk.NewDependencyWithID("example", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			PURL:           packageRef,
			Name:           "example",
			Version:        "1.0.0",
			PackageManager: manager,
		},
		ID:         "example",
		PackageRef: packageRef,
		Source:     sdk.DependencySourceRegistry,
	})
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: dependency.Coordinates,
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})
	return sdk.RemediationHintRequest{
		Detection: sdk.DetectionResult{
			SubprojectInfo: sdk.Subproject{
				DetectedPackageManagers: []sdk.PackageManager{manager},
			},
			Graphs: sdk.SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "manifest.file"}),
		},
		Registry: registry,
	}
}

func adviceForAction(response sdk.RemediationHintResponse, action sdk.RemediationAction) string {
	for _, hint := range response.Hints {
		for _, strategy := range hint.Strategies {
			if strategy.Action == action {
				return strategy.Advice
			}
		}
	}
	return ""
}

type detectorWithoutRemediation struct{}

func (detectorWithoutRemediation) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:              "detector-without-remediation",
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
	}
}

func (detectorWithoutRemediation) PackageManagerSupport() []sdk.PackageManagerSupport {
	return nil
}

func (detectorWithoutRemediation) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

func (detectorWithoutRemediation) Applicable(context.Context, sdk.DetectionRequest) (bool, error) {
	return true, nil
}

func (detectorWithoutRemediation) ResolveGraph(context.Context, sdk.DetectionRequest) (sdk.DetectionResult, error) {
	return sdk.DetectionResult{}, nil
}
