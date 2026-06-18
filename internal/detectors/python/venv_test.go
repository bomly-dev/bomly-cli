package python

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPythonVenvDirIsDeterministicAndScoped(t *testing.T) {
	a := pythonVenvDir("/tmp/project-a")
	b := pythonVenvDir("/tmp/project-b")
	if a == b {
		t.Errorf("different projects mapped to the same venv dir: %s", a)
	}
	if a != pythonVenvDir("/tmp/project-a") {
		t.Error("venv dir is not stable for the same working dir")
	}
	if filepath.Dir(a) != filepath.Clean(os.TempDir()) {
		t.Errorf("venv dir %s not under temp dir %s", a, os.TempDir())
	}
}

func TestVenvPythonPath(t *testing.T) {
	venvDir := t.TempDir()
	if got := venvPythonPath(venvDir); got != "" {
		t.Errorf("expected empty path for empty venv, got %q", got)
	}

	rel := filepath.Join("bin", "python")
	if runtime.GOOS == "windows" {
		rel = filepath.Join("Scripts", "python.exe")
	}
	pyPath := filepath.Join(venvDir, rel)
	if err := os.MkdirAll(filepath.Dir(pyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pyPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := venvPythonPath(venvDir); got != pyPath {
		t.Errorf("venvPythonPath = %q, want %q", got, pyPath)
	}
}

func TestPipInspectCommandPrefersVenv(t *testing.T) {
	// With no venv present the command falls back to the ambient interpreter.
	workingDir := t.TempDir()
	cmd, err := pipInspectCommandForProject(workingDir)
	if err != nil {
		t.Skipf("no ambient python available: %v", err)
	}
	if strings.Contains(strings.Join(cmd, " "), "bomly-pyvenv-") {
		t.Errorf("expected ambient interpreter without a venv, got %v", cmd)
	}

	// Create the project's venv python; the command must now target it.
	venvDir := pythonVenvDir(workingDir)
	rel := filepath.Join("bin", "python")
	if runtime.GOOS == "windows" {
		rel = filepath.Join("Scripts", "python.exe")
	}
	pyPath := filepath.Join(venvDir, rel)
	t.Cleanup(func() { _ = os.RemoveAll(venvDir) })
	if err := os.MkdirAll(filepath.Dir(pyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pyPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd, err = pipInspectCommandForProject(workingDir)
	if err != nil {
		t.Fatalf("pipInspectCommandForProject: %v", err)
	}
	if len(cmd) == 0 || cmd[0] != pyPath {
		t.Errorf("pipInspectCommandForProject = %v, want it to target %q", cmd, pyPath)
	}
}
