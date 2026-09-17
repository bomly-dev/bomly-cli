package bun

import (
	"context"
	"fmt"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func bunLockfileRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerBun},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionLockfileRefresh,
		},
	}}
}

// RemediationHints provides Bun-specific remediation guidance.
func (d LockfileDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerBun,
		bunLockfileRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionLockfileRefresh {
				return ""
			}
			return fmt.Sprintf("run bun update %s@%s", name, version)
		},
	), nil
}

func bunNativeRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerBun},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionLockfileRefresh,
		},
	}}
}

// RemediationHints provides Bun-specific remediation guidance.
func (d NativeDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerBun,
		bunNativeRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionLockfileRefresh {
				return ""
			}
			return fmt.Sprintf("run bun update %s@%s", name, version)
		},
	), nil
}
