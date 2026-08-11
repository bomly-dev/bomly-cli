package composer

import (
	"context"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

func composerRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerComposer},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides Composer-specific remediation guidance.
func (d Detector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerComposer,
		composerRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, manifestPath string) string {
			if action != sdk.RemediationActionTransitiveOverride {
				return ""
			}
			manifest := strings.TrimSpace(manifestPath)
			if manifest == "" {
				manifest = "the project manifest"
			}
			return fmt.Sprintf(`require %q: %q in %s and run composer update %s`, name, "^"+version, manifest, name)
		},
	), nil
}
