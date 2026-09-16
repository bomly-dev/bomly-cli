package python

import (
	"context"
	"fmt"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func pipRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerPip},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

func pipenvRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerPipenv},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

func poetryRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerPoetry},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

func uvRemediationCapabilities() []plugin.RemediationCapability {
	return []plugin.RemediationCapability{{
		SupportedManagers: []model.PackageManager{model.PackageManagerUV},
		Actions: []model.RemediationAction{
			model.RemediationActionDirectBump,
			model.RemediationActionTransitiveOverride,
		},
	}}
}

// RemediationHints provides pip-specific remediation guidance.
func (d PipDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerPip,
		pipRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf("add a constraint `%s>=%s` to your requirements or constraints file and reinstall", name, version)
		},
	), nil
}

// RemediationHints provides Pipenv-specific remediation guidance.
func (d PipenvDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerPipenv,
		pipenvRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf("add a constraint `%s>=%s` to your requirements or constraints file and reinstall", name, version)
		},
	), nil
}

// RemediationHints provides Poetry-specific remediation guidance.
func (d PoetryDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerPoetry,
		poetryRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf("pin `%s>=%s` in pyproject.toml and refresh the lockfile", name, version)
		},
	), nil
}

// RemediationHints provides uv-specific remediation guidance.
func (d UVDetector) RemediationHints(_ context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return detectors.BuildRemediationHints(
		request,
		model.PackageManagerUV,
		uvRemediationCapabilities()[0].Actions,
		func(action model.RemediationAction, name, version, _ string) string {
			if action != model.RemediationActionTransitiveOverride {
				return ""
			}
			return fmt.Sprintf("pin `%s>=%s` in pyproject.toml and refresh the lockfile", name, version)
		},
	), nil
}
