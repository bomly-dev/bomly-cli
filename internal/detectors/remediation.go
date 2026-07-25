package detectors

import (
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// RemediationCapabilities returns built-in read-only strategy support for the
// supplied package managers. Managers without a known strategy are omitted.
func RemediationCapabilities(managers []sdk.PackageManager) []sdk.RemediationCapability {
	capabilities := make([]sdk.RemediationCapability, 0, len(managers))
	seen := map[sdk.PackageManager]struct{}{}
	for _, manager := range managers {
		if _, ok := seen[manager]; ok {
			continue
		}
		seen[manager] = struct{}{}
		actions := remediationActions(manager)
		if len(actions) == 0 {
			continue
		}
		capabilities = append(capabilities, sdk.RemediationCapability{
			SupportedManagers: []sdk.PackageManager{manager},
			Actions:           actions,
		})
	}
	return capabilities
}

// RemediationHints is the shared implementation behind built-in detector
// providers. It returns detector-owned strategy advice through the public SDK
// hint contract. It never reads or writes project files, executes a subprocess,
// or performs network I/O.
func RemediationHints(
	request sdk.RemediationHintRequest,
	capabilities []sdk.RemediationCapability,
) sdk.RemediationHintResponse {
	if request.Detection.Graphs == nil || request.Registry == nil {
		return sdk.RemediationHintResponse{}
	}
	actionsByManager := map[sdk.PackageManager]map[sdk.RemediationAction]struct{}{}
	for _, capability := range capabilities {
		for _, manager := range capability.SupportedManagers {
			if actionsByManager[manager] == nil {
				actionsByManager[manager] = map[sdk.RemediationAction]struct{}{}
			}
			for _, action := range capability.Actions {
				actionsByManager[manager][action] = struct{}{}
			}
		}
	}

	response := sdk.RemediationHintResponse{}
	for _, entry := range request.Detection.Graphs.Entries {
		if entry.Graph == nil {
			continue
		}
		for _, dependency := range entry.Graph.Nodes() {
			if dependency == nil {
				continue
			}
			packageRef := dependency.PackageRef
			if packageRef == "" {
				packageRef = sdk.CanonicalPackageURLFromDependency(dependency)
			}
			if packageRef == "" {
				continue
			}
			pkg, ok := request.Registry.Get(packageRef)
			if !ok || pkg == nil || pkg.Remediation == nil ||
				pkg.Remediation.Status != sdk.PackageRemediationComplete ||
				strings.TrimSpace(pkg.Remediation.RecommendedVersion) == "" {
				continue
			}
			manager := dependency.PackageManager
			if manager == sdk.PackageManagerUnknown {
				manager = request.Detection.SubprojectInfo.PrimaryPackageManager()
			}
			actions := actionsByManager[manager]
			if len(actions) == 0 {
				continue
			}
			hint := sdk.RemediationHint{
				DependencyRef: dependency.ID,
				ManifestPath:  entry.Manifest.Path,
			}
			for _, action := range remediationActionOrder {
				if _, ok := actions[action]; !ok {
					continue
				}
				strategy := sdk.RemediationStrategyHint{
					Action: action,
					Advice: managerRemediationAdvice(
						manager,
						action,
						dependency.DisplayName(),
						pkg.Remediation.RecommendedVersion,
						entry.Manifest.Path,
					),
				}
				hint.Strategies = append(hint.Strategies, strategy)
			}
			if len(hint.Strategies) > 0 {
				response.Hints = append(response.Hints, hint)
			}
		}
	}
	return response
}

var remediationActionOrder = []sdk.RemediationAction{
	sdk.RemediationActionDirectBump,
	sdk.RemediationActionTransitiveOverride,
	sdk.RemediationActionLockfileRefresh,
}

func remediationActions(manager sdk.PackageManager) []sdk.RemediationAction {
	switch manager {
	case sdk.PackageManagerNPM,
		sdk.PackageManagerPNPM,
		sdk.PackageManagerYarn,
		sdk.PackageManagerMaven,
		sdk.PackageManagerGradle,
		sdk.PackageManagerPip,
		sdk.PackageManagerPipenv,
		sdk.PackageManagerPoetry,
		sdk.PackageManagerUV,
		sdk.PackageManagerBundler,
		sdk.PackageManagerComposer:
		return []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		}
	case sdk.PackageManagerGoMod,
		sdk.PackageManagerCargo,
		sdk.PackageManagerBun:
		return []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionLockfileRefresh,
		}
	default:
		return nil
	}
}

func managerRemediationAdvice(
	manager sdk.PackageManager,
	action sdk.RemediationAction,
	name, version, manifestPath string,
) string {
	switch action {
	case sdk.RemediationActionTransitiveOverride:
		return transitiveOverrideAdvice(manager, name, version, manifestPath)
	case sdk.RemediationActionLockfileRefresh:
		return lockfileRefreshAdvice(manager, name, version)
	default:
		return ""
	}
}

func transitiveOverrideAdvice(manager sdk.PackageManager, name, version, manifestPath string) string {
	manifest := strings.TrimSpace(manifestPath)
	if manifest == "" {
		manifest = "the project manifest"
	}
	switch manager {
	case sdk.PackageManagerNPM:
		return fmt.Sprintf(`add "overrides": {%q: %q} to package.json and run npm install`, name, version)
	case sdk.PackageManagerPNPM:
		return fmt.Sprintf(`add %q: %q under "pnpm"."overrides" in package.json (or under "overrides:" in pnpm-workspace.yaml for workspaces) and run pnpm install`, name, version)
	case sdk.PackageManagerYarn:
		return fmt.Sprintf(`add "resolutions": {%q: %q} to package.json and run yarn install`, name, version)
	case sdk.PackageManagerMaven:
		return fmt.Sprintf("pin %s to %s in <dependencyManagement> of %s", name, version, manifest)
	case sdk.PackageManagerGradle:
		return fmt.Sprintf("add dependencies { constraints { implementation(%q) } } in %s", name+":"+version, manifest)
	case sdk.PackageManagerPip, sdk.PackageManagerPipenv:
		return fmt.Sprintf("add a constraint `%s>=%s` to your requirements or constraints file and reinstall", name, version)
	case sdk.PackageManagerPoetry, sdk.PackageManagerUV:
		return fmt.Sprintf("pin `%s>=%s` in pyproject.toml and refresh the lockfile", name, version)
	case sdk.PackageManagerBundler:
		return fmt.Sprintf(`add gem %q, ">= %s" to the Gemfile and run bundle update %s`, name, version, name)
	case sdk.PackageManagerComposer:
		return fmt.Sprintf(`require %q: %q in %s and run composer update %s`, name, "^"+version, manifest, name)
	default:
		return ""
	}
}

func lockfileRefreshAdvice(manager sdk.PackageManager, name, version string) string {
	switch manager {
	case sdk.PackageManagerGoMod:
		return fmt.Sprintf("run go get %s@v%s && go mod tidy", name, strings.TrimPrefix(version, "v"))
	case sdk.PackageManagerCargo:
		return fmt.Sprintf("run cargo update -p %s --precise %s", name, version)
	case sdk.PackageManagerBun:
		return fmt.Sprintf("run bun update %s@%s", name, version)
	default:
		return ""
	}
}
