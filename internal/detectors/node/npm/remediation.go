package npm

import (
	"context"
	"fmt"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func npmLockfileRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides npm-specific remediation guidance.
func (d LockfileDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerNPM,
		npmLockfileRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf(`add "overrides": {%q: %q} to package.json and run npm install`, name, version)
		},
	), nil
}

func npmNativeRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides npm-specific remediation guidance.
func (d NativeDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerNPM,
		npmNativeRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf(`add "overrides": {%q: %q} to package.json and run npm install`, name, version)
		},
	), nil
}
