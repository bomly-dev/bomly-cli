package registry

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestBuiltInDetectorsOwnRemediationCapabilitiesAndAdvice(t *testing.T) {
	testCases := []struct {
		name    string
		manager model.PackageManager
		action  model.RemediationAction
		advice  string
	}{
		{detectors.NameNPM, model.PackageManagerNPM, model.RemediationActionTransitiveOverride, `add "overrides": {"example": "1.2.0"} to package.json and run npm install`},
		{detectors.NamePNPM, model.PackageManagerPNPM, model.RemediationActionTransitiveOverride, `add "example": "1.2.0" under "pnpm"."overrides" in package.json (or under "overrides:" in pnpm-workspace.yaml for workspaces) and run pnpm install`},
		{detectors.NameYarn, model.PackageManagerYarn, model.RemediationActionTransitiveOverride, `add "resolutions": {"example": "1.2.0"} to package.json and run yarn install`},
		{detectors.NameBun, model.PackageManagerBun, model.RemediationActionLockfileRefresh, "run bun update example@1.2.0"},
		{detectors.NameBunNative, model.PackageManagerBun, model.RemediationActionLockfileRefresh, "run bun update example@1.2.0"},
		{detectors.NameGoMod, model.PackageManagerGoMod, model.RemediationActionLockfileRefresh, "run go get example@v1.2.0 && go mod tidy"},
		{detectors.NameCargo, model.PackageManagerCargo, model.RemediationActionLockfileRefresh, "run cargo update -p example --precise 1.2.0"},
		{detectors.NameMaven, model.PackageManagerMaven, model.RemediationActionTransitiveOverride, "pin example to 1.2.0 in <dependencyManagement> of manifest.file"},
		{detectors.NameGradle, model.PackageManagerGradle, model.RemediationActionTransitiveOverride, `add dependencies { constraints { implementation("example:1.2.0") } } in manifest.file`},
		{detectors.NamePip, model.PackageManagerPip, model.RemediationActionTransitiveOverride, "add a constraint `example>=1.2.0` to your requirements or constraints file and reinstall"},
		{detectors.NamePipenv, model.PackageManagerPipenv, model.RemediationActionTransitiveOverride, "add a constraint `example>=1.2.0` to your requirements or constraints file and reinstall"},
		{detectors.NamePoetry, model.PackageManagerPoetry, model.RemediationActionTransitiveOverride, "pin `example>=1.2.0` in pyproject.toml and refresh the lockfile"},
		{detectors.NameUV, model.PackageManagerUV, model.RemediationActionTransitiveOverride, "pin `example>=1.2.0` in pyproject.toml and refresh the lockfile"},
		{detectors.NameBundler, model.PackageManagerBundler, model.RemediationActionTransitiveOverride, `add gem "example", ">= 1.2.0" to the Gemfile and run bundle update example`},
		{detectors.NameComposer, model.PackageManagerComposer, model.RemediationActionTransitiveOverride, `require "example": "^1.2.0" in manifest.file and run composer update example`},
	}

	builtIns := make(map[string]plugin.Detector)
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
			provider, ok := detector.(plugin.DetectorRemediationProvider)
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
		Origin:         plugin.CoreOrigin,
	})

	descriptors := reg.DetectorDescriptors()
	if len(descriptors) != 1 {
		t.Fatalf("DetectorDescriptors() length = %d, want 1", len(descriptors))
	}
	if len(descriptors[0].RemediationCapabilities) != 0 {
		t.Fatalf("registry inferred remediation capabilities: %#v", descriptors[0].RemediationCapabilities)
	}
	if _, ok := reg.AllDetectors()[0].(plugin.DetectorRemediationProvider); ok {
		t.Fatal("registry added the remediation provider contract to an unsupported detector")
	}
}

func remediationHintRequest(t *testing.T, manager model.PackageManager) plugin.RemediationHintRequest {
	t.Helper()
	const packageRef = "pkg:generic/example@1.0.0"
	graph := model.New()
	dependency := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{
			PURL:           packageRef,
			Name:           "example",
			Version:        "1.0.0",
			PackageManager: manager,
		},
		PackageRef: packageRef,
		Source:     model.DependencySourceRegistry,
	})
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates: dependency.Coordinates,
		Remediation: &model.PackageRemediation{
			Status:             model.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})
	return plugin.RemediationHintRequest{
		Detection: plugin.DetectionResult{
			SubprojectInfo: plugin.Subproject{
				DetectedPackageManagers: []model.PackageManager{manager},
			},
			Graphs: model.SingleGraphContainer(graph, model.ManifestMetadata{Path: "manifest.file"}),
		},
		Registry: registry,
	}
}

func adviceForAction(response plugin.RemediationHintResponse, action model.RemediationAction) string {
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

func (detectorWithoutRemediation) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		Name:              "detector-without-remediation",
		SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
	}
}

func (detectorWithoutRemediation) PackageManagerSupport() []plugin.PackageManagerSupport {
	return nil
}

func (detectorWithoutRemediation) Ready(context.Context, plugin.DetectionRequest) error {
	return nil
}

func (detectorWithoutRemediation) Applicable(context.Context, plugin.DetectionRequest) (bool, error) {
	return true, nil
}

func (detectorWithoutRemediation) ResolveGraph(context.Context, plugin.DetectionRequest) (plugin.DetectionResult, error) {
	return plugin.DetectionResult{}, nil
}
