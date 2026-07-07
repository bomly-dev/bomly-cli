package python

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

var sensitiveCommandFlags = map[string]struct{}{
	"--password":      {},
	"--token":         {},
	"--access-token":  {},
	"--client-secret": {},
	"--secret":        {},
	"--key":           {},
}

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
		out.InstallCommand = sanitizeCommand(installCommand)
		out.InstallWorkingDir = workingDir
	}
	return out
}

func sanitizeCommand(command []string) []string {
	out := make([]string, len(command))
	redactNext := false
	for i, value := range command {
		if redactNext {
			out[i] = "[REDACTED]"
			redactNext = false
			continue
		}
		if flag, valuePart, ok := strings.Cut(value, "="); ok {
			if _, sensitive := sensitiveCommandFlags[flag]; sensitive {
				out[i] = flag + "=[REDACTED]"
				continue
			}
			out[i] = flag + "=" + redactURL(valuePart)
			continue
		}
		if _, sensitive := sensitiveCommandFlags[value]; sensitive {
			out[i] = value
			redactNext = true
			continue
		}
		out[i] = redactURL(value)
	}
	return out
}

func redactURL(value string) string {
	if !strings.Contains(value, "://") {
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User == nil {
		return value
	}
	parsed.User = url.User("[REDACTED]")
	return parsed.String()
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
