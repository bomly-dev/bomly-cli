package ruby

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func bundlerRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerBundler},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides Bundler-specific remediation guidance.
func (d Detector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerBundler,
		bundlerRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf(`add gem %q, ">= %s" to the Gemfile and run bundle update %s`, name, version, name)
		},
	), nil
}
