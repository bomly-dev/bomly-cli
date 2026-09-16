package ruby

import (
	"context"
	"fmt"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func bundlerRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerBundler},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides Bundler-specific remediation guidance.
func (d Detector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerBundler,
		bundlerRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf(`add gem %q, ">= %s" to the Gemfile and run bundle update %s`, name, version, name)
		},
	), nil
}
