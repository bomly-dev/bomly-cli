package bun

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func bunLockfileRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerBun},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionLockfileRefresh,
		},
	}}
}

// RemediationHints provides Bun-specific remediation guidance.
func (d LockfileDetector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerBun,
		bunLockfileRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionLockfileRefresh {
				return ""
			}
			return fmt.Sprintf("run bun update %s@%s", name, version)
		},
	), nil
}

func bunNativeRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerBun},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionLockfileRefresh,
		},
	}}
}

// RemediationHints provides Bun-specific remediation guidance.
func (d NativeDetector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerBun,
		bunNativeRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionLockfileRefresh {
				return ""
			}
			return fmt.Sprintf("run bun update %s@%s", name, version)
		},
	), nil
}
