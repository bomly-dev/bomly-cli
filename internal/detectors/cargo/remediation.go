package cargo

import (
	"context"
	"fmt"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func cargoRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerCargo},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionLockfileRefresh,
		},
	}}
}

// RemediationHints provides Cargo-specific remediation guidance.
func (d Detector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerCargo,
		cargoRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionLockfileRefresh {
				return ""
			}
			return fmt.Sprintf("run cargo update -p %s --precise %s", name, version)
		},
	), nil
}
