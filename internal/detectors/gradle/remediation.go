package gradle

import (
	"context"
	"fmt"
	"strings"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func gradleRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerGradle},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides Gradle-specific remediation guidance.
func (d Detector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerGradle,
		gradleRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, manifestPath string) string {
			if action != model.RemediationActionTransitiveOverride {
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
