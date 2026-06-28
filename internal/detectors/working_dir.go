package detectors

import (
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// RequestWorkingDir returns the directory a detector should operate in for the
// given request, preferring the explicit project path and falling back to the
// subproject execution target location.
func RequestWorkingDir(req sdk.DetectionRequest) string {
	if wd := strings.TrimSpace(req.ProjectPath); wd != "" {
		return wd
	}
	return strings.TrimSpace(req.ExecutionTarget.Location)
}
