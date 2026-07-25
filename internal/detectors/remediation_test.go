package detectors

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestRemediationCapabilitiesDescribeBuiltInStrategies(t *testing.T) {
	capabilities := RemediationCapabilities([]sdk.PackageManager{
		sdk.PackageManagerNPM,
		sdk.PackageManagerGoMod,
		sdk.PackageManagerNPM,
		sdk.PackageManagerUnknown,
	})
	if len(capabilities) != 2 {
		t.Fatalf("RemediationCapabilities() = %#v, want two supported managers", capabilities)
	}
	if got := capabilities[0].Actions; !containsRemediationAction(got, sdk.RemediationActionDirectBump) ||
		!containsRemediationAction(got, sdk.RemediationActionTransitiveOverride) {
		t.Fatalf("npm actions = %#v", got)
	}
	if got := capabilities[1].Actions; !containsRemediationAction(got, sdk.RemediationActionDirectBump) ||
		!containsRemediationAction(got, sdk.RemediationActionLockfileRefresh) {
		t.Fatalf("gomod actions = %#v", got)
	}
}

func TestTransitiveOverrideAdvicePerPackageManager(t *testing.T) {
	cases := []struct {
		manager  sdk.PackageManager
		contains []string
	}{
		{sdk.PackageManagerPNPM, []string{`"js-yaml": "3.15.0"`, "pnpm-workspace.yaml", "pnpm install"}},
		{sdk.PackageManagerNPM, []string{`"overrides"`, `"js-yaml": "3.15.0"`}},
		{sdk.PackageManagerYarn, []string{`"resolutions"`, "yarn install"}},
		{sdk.PackageManagerMaven, []string{"<dependencyManagement>"}},
		{sdk.PackageManagerGradle, []string{"constraints"}},
		{sdk.PackageManagerPip, []string{"js-yaml>=3.15.0"}},
		{sdk.PackageManagerPoetry, []string{"pyproject.toml"}},
		{sdk.PackageManagerBundler, []string{`gem "js-yaml"`}},
		{sdk.PackageManagerComposer, []string{"composer update js-yaml"}},
	}
	for _, tc := range cases {
		t.Run(tc.manager.Name(), func(t *testing.T) {
			advice := transitiveOverrideAdvice(tc.manager, "js-yaml", "3.15.0", "pnpm-workspace.yaml")
			for _, want := range tc.contains {
				if !strings.Contains(advice, want) {
					t.Fatalf("advice %q does not contain %q", advice, want)
				}
			}
		})
	}
}

func TestLockfileRefreshAdvicePerPackageManager(t *testing.T) {
	cases := []struct {
		manager sdk.PackageManager
		want    string
	}{
		{sdk.PackageManagerGoMod, "run go get example.com/lib@v1.2.0 && go mod tidy"},
		{sdk.PackageManagerCargo, "run cargo update -p example.com/lib --precise 1.2.0"},
		{sdk.PackageManagerBun, "run bun update example.com/lib@1.2.0"},
	}
	for _, tc := range cases {
		t.Run(tc.manager.Name(), func(t *testing.T) {
			got := lockfileRefreshAdvice(tc.manager, "example.com/lib", "1.2.0")
			if got != tc.want {
				t.Fatalf("lockfileRefreshAdvice() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRemediationHintsResolveRawDetectionCoordinates(t *testing.T) {
	graph := sdk.New()
	dependency := sdk.NewDependencyWithID("raw-lockfile-id", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Name:      "example",
			Version:   "1.0.0",
			Ecosystem: sdk.EcosystemNPM,
			Type:      sdk.PackageTypePackage,
		},
		ID:           "raw-lockfile-id",
		Relationship: sdk.DependencyRelationshipDirect,
		Source:       sdk.DependencySourceRegistry,
	})
	if dependency.PackageRef != "" {
		t.Fatalf("test requires a raw dependency without PackageRef: %#v", dependency)
	}
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{
			PURL:    "pkg:npm/example@1.0.0",
			Name:    "example",
			Version: "1.0.0",
		},
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})

	response := RemediationHints(sdk.RemediationHintRequest{
		Detection: sdk.DetectionResult{
			SubprojectInfo: sdk.Subproject{
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			},
			Graphs: sdk.SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "package-lock.json"}),
		},
		Registry: registry,
	}, RemediationCapabilities([]sdk.PackageManager{sdk.PackageManagerNPM}))
	if len(response.Hints) != 1 || response.Hints[0].DependencyRef != dependency.ID {
		t.Fatalf("RemediationHints() = %#v", response)
	}
	if !containsHintAction(response.Hints[0].Strategies, sdk.RemediationActionDirectBump) {
		t.Fatalf("direct strategy missing: %#v", response.Hints[0])
	}
}

func TestRemediationHintsIncludesLockfileRefreshAdvice(t *testing.T) {
	graph := sdk.New()
	dependency := sdk.NewDependencyWithID("example.com/lib", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			PURL: "pkg:golang/example.com/lib@1.0.0", Name: "example.com/lib",
			Version: "1.0.0", PackageManager: sdk.PackageManagerGoMod,
		},
		ID:         "example.com/lib",
		PackageRef: "pkg:golang/example.com/lib@1.0.0",
		Source:     sdk.DependencySourceRegistry,
	})
	if err := graph.AddNode(dependency); err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: dependency.Coordinates,
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})
	response := RemediationHints(sdk.RemediationHintRequest{
		Detection: sdk.DetectionResult{
			SubprojectInfo: sdk.Subproject{
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerGoMod},
			},
			Graphs: sdk.SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "go.mod"}),
		},
		Registry: registry,
	}, RemediationCapabilities([]sdk.PackageManager{sdk.PackageManagerGoMod}))
	if len(response.Hints) != 1 {
		t.Fatalf("RemediationHints() = %#v", response)
	}
	for _, strategy := range response.Hints[0].Strategies {
		if strategy.Action == sdk.RemediationActionLockfileRefresh {
			if strategy.Advice != "run go get example.com/lib@v1.2.0 && go mod tidy" {
				t.Fatalf("lockfile refresh advice = %q", strategy.Advice)
			}
			return
		}
	}
	t.Fatalf("lockfile refresh strategy missing: %#v", response.Hints[0])
}

func containsRemediationAction(actions []sdk.RemediationAction, target sdk.RemediationAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

func containsHintAction(strategies []sdk.RemediationStrategyHint, target sdk.RemediationAction) bool {
	for _, strategy := range strategies {
		if strategy.Action == target {
			return true
		}
	}
	return false
}
