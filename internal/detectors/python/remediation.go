package python

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-sdk"
	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"
)

func pipRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerPip},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

func pipenvRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerPipenv},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

func poetryRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerPoetry},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

func uvRemediationCapabilities() []sdk.RemediationCapability {
	return []sdk.RemediationCapability{{
		SupportedManagers: []sdk.PackageManager{sdk.PackageManagerUV},
		Actions: []sdk.RemediationAction{
			sdk.RemediationActionDirectBump,
			sdk.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides pip-specific remediation guidance.
func (d PipDetector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerPip,
		pipRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf("add a constraint `%s>=%s` to your requirements or constraints file and reinstall", name, version)
		},
	), nil
}

// RemediationHints provides Pipenv-specific remediation guidance.
func (d PipenvDetector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerPipenv,
		pipenvRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf("add a constraint `%s>=%s` to your requirements or constraints file and reinstall", name, version)
		},
	), nil
}

// RemediationHints provides Poetry-specific remediation guidance.
func (d PoetryDetector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerPoetry,
		poetryRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf("pin `%s>=%s` in pyproject.toml and refresh the lockfile", name, version)
		},
	), nil
}

// RemediationHints provides uv-specific remediation guidance.
func (d UVDetector) RemediationHints(_ context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		sdk.PackageManagerUV,
		uvRemediationCapabilities()[0].Actions,
		func(action sdk.RemediationAction, name, version, _ string) string {
			if action != sdk.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf("pin `%s>=%s` in pyproject.toml and refresh the lockfile", name, version)
		},
	), nil
}
