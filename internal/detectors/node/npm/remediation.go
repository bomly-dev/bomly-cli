package npm

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func npmLockfileRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides npm-specific remediation guidance.
func (d LockfileDetector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerNPM,
		npmLockfileRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf(`add "overrides": {%q: %q} to package.json and run npm install`, name, version)
		},
	), nil
}

func npmNativeRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides npm-specific remediation guidance.
func (d NativeDetector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerNPM,
		npmNativeRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf(`add "overrides": {%q: %q} to package.json and run npm install`, name, version)
		},
	), nil
}
