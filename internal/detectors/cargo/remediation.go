package cargo

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-sdk"
	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"
)

func cargoRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerCargo},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionLockfileRefresh,
		},
	}}
}

// RemediationHints provides Cargo-specific remediation guidance.
func (d Detector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerCargo,
		cargoRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionLockfileRefresh {
				return ""
			}
			return fmt.Sprintf("run cargo update -p %s --precise %s", name, version)
		},
	), nil
}
