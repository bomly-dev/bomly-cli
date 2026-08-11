package gradle

import (
	"context"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

func gradleRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerGradle},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides Gradle-specific remediation guidance.
func (d Detector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerGradle,
		gradleRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, manifestPath string) string {
			if action != sdk.RemediationActionTransitiveOverride {
				return ""
			}
			manifest := strings.TrimSpace(manifestPath)
			if manifest == "" {
				manifest = "the project manifest"
			}
			return fmt.Sprintf("add dependencies { constraints { implementation(%q) } } in %s", name+":"+version, manifest)
		},
	), nil
}
