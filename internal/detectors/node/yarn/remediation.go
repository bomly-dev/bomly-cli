package yarn

import (
	"context"
	"fmt"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func yarnLockfileRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerYarn},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides Yarn-specific remediation guidance.
func (d LockfileDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerYarn,
		yarnLockfileRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf(`add "resolutions": {%q: %q} to package.json and run yarn install`, name, version)
		},
	), nil
}

func yarnNativeRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerYarn},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides Yarn-specific remediation guidance.
func (d NativeDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerYarn,
		yarnNativeRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf(`add "resolutions": {%q: %q} to package.json and run yarn install`, name, version)
		},
	), nil
}
