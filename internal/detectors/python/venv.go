package python

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-sdk"
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
	fields := []zap.Field{zap.String("detector", detectorName), zap.String("venv", venvDir)}
	fields = append(fields, logging.CommandFields(command[0], command[1:], cmd.Dir)...)
	logger.Debug("creating python virtualenv", fields...)
	if err := cmd.Run(); err != nil {
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.ByteCount() > 0 {
			fields = append(fields, zap.Int64("stderr_bytes", commandStderr.ByteCount()))
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

// minPipInspectMajor / minPipInspectMinor pin the first pip release that ships
// `pip inspect` (22.2). Older pip exits non-zero with an unknown-command error
// that says nothing about the version.
const (
	minPipInspectMajor = 22
	minPipInspectMinor = 2
	minPipInspectLabel = "22.2"
)

var pipVersionPattern = regexp.MustCompile(`pip\s+(\d+)\.(\d+)`)

// verifyPipInspectSupport reports whether the freshly created virtualenv can
// be inspected at all. `python -m venv` seeds the venv with the ambient
// interpreter's pip, so an old system Python (macOS ships 3.9 with pip 21.x)
// produces a venv whose pip has no `inspect` command and exits non-zero with a
// message that says nothing about the version.
//
// Bomly diagnoses this rather than fixing it: installing or upgrading a
// package manager is out of scope, and the check runs before the install so a
// doomed resolution costs nothing. The detector's fallback still produces a
// graph; the difference is that the degradation notice now names the pip
// version and the minimum instead of reporting "exit status 1".
func verifyPipInspectSupport(base baseDetector, req sdk.DetectionRequest, detectorName, venvPython string) error {
	logger := base.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	version, err := readPipVersion(base, req, detectorName, venvPython, logger)
	if err != nil {
		// An unreadable version is not itself fatal: let the install and
		// inspect steps report whatever is actually wrong.
		logger.Debug("could not read pip version from isolated environment", zap.String("detector", detectorName), zap.Error(err))
		return nil
	}
	if pipSupportsInspect(version) {
		logger.Debug("isolated environment pip supports inspect", zap.String("detector", detectorName), zap.String("pip_version", version))
		return nil
	}
	return fmt.Errorf("isolated environment has pip %s, but `pip inspect` requires pip %s or newer; upgrade pip for that interpreter (python -m pip install --upgrade pip) or put a newer Python on PATH", version, minPipInspectLabel)
}

// readPipVersion returns the version string reported by `python -m pip
// --version` for the given interpreter (e.g. "21.2.4").
func readPipVersion(base baseDetector, req sdk.DetectionRequest, detectorName, venvPython string, logger *zap.Logger) (string, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	command := []string{venvPython, "-m", "pip", "--version"}
	cmd := system.Command(command[0], command[1:]...)
	cmd.Dir = base.workingDir(req.ProjectPath)
	cmd.Env = pythonCommandEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = logging.NewCommandStderr(req.Stderr, req.Verbose)
	logger.Debug("checking isolated environment pip version", zap.String("detector", detectorName), zap.String("working_dir", cmd.Dir), zap.String("executable", command[0]), zap.Strings("args", command[1:]))
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("run %s pip --version: %w", detectorName, err)
	}
	// "pip 21.2.4 from /path/to/pip (python 3.9)"
	fields := strings.Fields(out.String())
	if len(fields) < 2 || fields[0] != "pip" {
		return "", fmt.Errorf("unrecognized pip --version output %q", strings.TrimSpace(out.String()))
	}
	return fields[1], nil
}

// pipSupportsInspect reports whether a pip version string is new enough to
// provide `pip inspect`.
func pipSupportsInspect(version string) bool {
	match := pipVersionPattern.FindStringSubmatch("pip " + strings.TrimSpace(version))
	if len(match) != 3 {
		// Unparseable versions (dev builds, vendored forks) are given the
		// benefit of the doubt; the inspect step reports the real failure.
		return true
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return true
	}
	minor, err := strconv.Atoi(match[2])
	if err != nil {
		return true
	}
	if major != minPipInspectMajor {
		return major > minPipInspectMajor
	}
	return minor >= minPipInspectMinor
}
