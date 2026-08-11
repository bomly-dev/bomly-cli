package maven

import (
	"context"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

func mavenRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerMaven},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides Maven-specific remediation guidance.
func (d Detector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerMaven,
		mavenRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, manifestPath string) string {
			if action != sdk.RemediationActionTransitiveOverride {
				return ""
			}
			manifest := strings.TrimSpace(manifestPath)
			if manifest == "" {
				manifest = "the project manifest"
			}
			return fmt.Sprintf("pin %s to %s in <dependencyManagement> of %s", name, version, manifest)
		},
	), nil
}
