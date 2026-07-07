package python

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// pythonVenvDir returns a deterministic, project-scoped virtualenv directory.
// The install-first step populates it and graph resolution inspects it, so both
// phases must derive the same path from the same working dir.
func pythonVenvDir(workingDir string) string {
	abs, err := filepath.Abs(workingDir)
	if err != nil {
		abs = workingDir
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(os.TempDir(), "bomly-pyvenv-"+hex.EncodeToString(sum[:8]))
}

// venvPythonPath returns the python executable inside venvDir, or "" when the
// venv has not been created yet.
func venvPythonPath(venvDir string) string {
	candidate := filepath.Join(venvDir, "bin", "python")
	if runtime.GOOS == "windows" {
		candidate = filepath.Join(venvDir, "Scripts", "python.exe")
	}
	if ok, _ := system.FileExists(candidate); ok {
		return candidate
	}
	return ""
}

// pipInspectCommandForProject prefers the project's isolated venv for
// `pip inspect`, falling back to the ambient interpreter when no venv exists
// (i.e. install-first was not run). Inspecting the venv keeps the resolved
// graph free of whatever unrelated tooling lives in the ambient site-packages.
func pipInspectCommandForProject(workingDir string) ([]string, error) {
	if py := venvPythonPath(pythonVenvDir(workingDir)); py != "" {
		return []string{py, "-m", "pip", "inspect", "--local"}, nil
	}
	return pipInspectCommand()
}

// createPythonVenv (re)creates a clean virtualenv at venvDir using the ambient
// interpreter and returns the path to the venv's python executable. The venv is
// recreated from scratch so a stale environment never leaks into resolution.
func createPythonVenv(ctx context.Context, base baseDetector, req sdk.DetectionRequest, detectorName, venvDir string) (string, error) {
	logger := base.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	if err := os.RemoveAll(venvDir); err != nil {
		return "", fmt.Errorf("reset venv %s: %w", venvDir, err)
	}
	pythonCmd, err := pythonCommand()
	if err != nil {
		return "", err
	}
	command := append(append([]string{}, pythonCmd...), "-m", "venv", venvDir)

	cmd := system.Command(command[0], command[1:]...)
	cmd.Dir = base.workingDir(req.ProjectPath)
	cmd.Env = pythonCommandEnv()
	commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr
	started := time.Now()
	logger.Info(fmt.Sprintf("%s creating isolated virtualenv", detectorName))
	sanitizedCommand := sanitizeCommand(command)
	logger.Debug("creating python virtualenv", zap.String("detector", detectorName), zap.String("working_dir", cmd.Dir), zap.String("venv", venvDir), zap.String("executable", sanitizedCommand[0]), zap.Strings("args", sanitizedCommand[1:]))
	if err := cmd.Run(); err != nil {
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("python virtualenv creation failed", fields...)
		return "", fmt.Errorf("create venv: %w", err)
	}
	logger.Info(fmt.Sprintf("%s virtualenv ready in %s", detectorName, logging.FormatDuration(time.Since(started))))

	venvPython := venvPythonPath(venvDir)
	if venvPython == "" {
		return "", fmt.Errorf("venv python not found under %s", venvDir)
	}
	return venvPython, nil
}
