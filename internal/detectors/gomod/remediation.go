package gomod

import (
	"context"
	"fmt"
	"strings"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func goModRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerGoMod},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionLockfileRefresh,
		},
	}}
}

// RemediationHints provides Go-module-specific remediation guidance.
func (d Detector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerGoMod,
		goModRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionLockfileRefresh {
				return ""
			}
			return fmt.Sprintf("run go get %s@v%s && go mod tidy", name, strings.TrimPrefix(version, "v"))
		},
	), nil
}
