package gomod

import (
	"context"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func goModRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerGoMod},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionLockfileRefresh,
		},
	}}
}

// RemediationHints provides Go-module-specific remediation guidance.
func (d Detector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerGoMod,
		goModRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionLockfileRefresh {
				return ""
			}
			return fmt.Sprintf("run go get %s@v%s && go mod tidy", name, strings.TrimPrefix(version, "v"))
		},
	), nil
}
