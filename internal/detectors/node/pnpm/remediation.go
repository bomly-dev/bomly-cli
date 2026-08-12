package pnpm

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-sdk"
	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"
)

func pnpmLockfileRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerPNPM},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides pnpm-specific remediation guidance.
func (d LockfileDetector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerPNPM,
		pnpmLockfileRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionTransitiveOverride {
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

func pnpmNativeRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerPNPM},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides pnpm-specific remediation guidance.
func (d NativeDetector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerPNPM,
		pnpmNativeRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionTransitiveOverride {
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
