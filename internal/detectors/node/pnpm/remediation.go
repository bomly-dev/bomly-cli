package pnpm

import (
	"context"
	"fmt"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func pnpmLockfileRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerPNPM},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides pnpm-specific remediation guidance.
func (d LockfileDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerPNPM,
		pnpmLockfileRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf(
				`add %q: %q under "pnpm"."overrides" in package.json (or under "overrides:" in pnpm-workspace.yaml for workspaces) and run pnpm install`,
				name,
				version,
			)
		},
	), nil
}

func pnpmNativeRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerPNPM},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides pnpm-specific remediation guidance.
func (d NativeDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerPNPM,
		pnpmNativeRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf(
				`add %q: %q under "pnpm"."overrides" in package.json (or under "overrides:" in pnpm-workspace.yaml for workspaces) and run pnpm install`,
				name,
				version,
			)
		},
	), nil
}
