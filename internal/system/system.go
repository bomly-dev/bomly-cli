package system

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// Abs resolves a path to an absolute path.
func Abs(path string) (string, error) {
	return filepath.Abs(path)
}

// Command constructs an external process command.
func Command(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

// Environ returns the current process environment.
func Environ() []string {
	return os.Environ()
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
