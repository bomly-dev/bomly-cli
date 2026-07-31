package python

import (
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func manifestWithResolution(req sdk.DetectionRequest, patterns []string, resolution *sdk.ResolutionMetadata) sdk.ManifestMetadata {
	manifest := detectors.InferManifestMetadata(req, patterns)
	manifest.Resolution = resolution
	return manifest
}

func resolutionMetadata(method sdk.ResolutionMethod, installExecuted bool, installCommand []string, workingDir string) *sdk.ResolutionMetadata {
	out := &sdk.ResolutionMetadata{
		Method:          method,
		InstallExecuted: installExecuted,
	}
	if installExecuted && len(installCommand) > 0 {
		out.InstallCommand = logging.SanitizeArgs(installCommand)
		out.InstallWorkingDir = workingDir
	}
	return out
}

func logResolution(logger *zap.Logger, detectorName string, workingDir string, resolution *sdk.ResolutionMetadata) {
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
