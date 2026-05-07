package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Abs resolves a path to an absolute path.
func Abs(path string) (string, error) {
	return filepath.Abs(path)
}

// Command constructs an external process command.
func Command(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

// FileExists reports whether path exists and is a file.
func FileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		return !info.IsDir(), nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// Getwd returns the current working directory.
func Getwd() (string, error) {
	return os.Getwd()
}

// LookPath resolves a command on PATH.
func LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// PathEnv returns the current PATH value.
func PathEnv() string {
	return os.Getenv("PATH")
}

// UserHomeDir returns the current user's home directory.
func UserHomeDir() (string, error) {
	return os.UserHomeDir()
}

// ResolveExistingFile resolves pathValue to an absolute path and validates that it exists as a file.
func ResolveExistingFile(pathValue string) (string, error) {
	selectedPath := strings.TrimSpace(pathValue)
	if selectedPath == "" {
		return "", fmt.Errorf("path is required")
	}
	absPath, err := Abs(selectedPath)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", selectedPath, err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path %q does not exist", selectedPath)
		}
		return "", fmt.Errorf("stat path %q: %w", selectedPath, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("path %q is a directory", selectedPath)
	}
	return absPath, nil
}
