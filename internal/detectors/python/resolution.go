package python

import (
	"fmt"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"
	logging "github.com/bomly-dev/bomly-sdk/logkit"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func manifestWithResolution(req plugin.DetectionRequest, patterns []string, resolution *model.ResolutionMetadata) model.ManifestMetadata {
	manifest := detectors.InferManifestMetadata(req, patterns)
	manifest.Resolution = resolution
	return manifest
}

func resolutionMetadata(method model.ResolutionMethod, installExecuted bool, installCommand []string, workingDir string) *model.ResolutionMetadata {
	out := &model.ResolutionMetadata{
		Method:          method,
		InstallExecuted: installExecuted,
	}
	if installExecuted && len(installCommand) > 0 {
		out.InstallCommand = logging.SanitizeArgs(installCommand)
		out.InstallWorkingDir = workingDir
	}
	return out
}

func logResolution(logger *zap.Logger, detectorName string, workingDir string, resolution *model.ResolutionMetadata) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if resolution == nil {
		return
	}
	fields := []zap.Field{
		zap.String("detector", detectorName),
		zap.String("working_dir", workingDir),
		zap.String("method", string(resolution.Method)),
		zap.Bool("install_executed", resolution.InstallExecuted),
	}
	if len(resolution.InstallCommand) > 0 {
		fields = append(fields, zap.Strings("install_command", resolution.InstallCommand))
	}
	logger.Info(fmt.Sprintf("%s resolved dependencies using %s", detectorName, resolution.Method), fields...)
}
