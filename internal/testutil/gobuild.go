package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/system"
)

// BuildGoBinary writes source to a temporary file and builds it into outputPath.
func BuildGoBinary(t testing.TB, outputPath, source string) error {
	t.Helper()

	srcPath := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		return err
	}
	return buildGoBinary(outputPath, srcPath)
}

// BuildGoBinaryFromSource is BuildGoBinary for callers without a testing
// handle — package TestMain functions that build shared fake binaries once.
// It manages its own temporary source directory.
func BuildGoBinaryFromSource(outputPath, source string) error {
	srcDir, err := os.MkdirTemp("", "bomly-testbin-src-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(srcDir) }()

	srcPath := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		return err
	}
	return buildGoBinary(outputPath, srcPath)
}

func buildGoBinary(outputPath, srcPath string) error {
	buildCmd := system.Command("go", "build", "-o", outputPath, srcPath)
	buildCmd.Env = append(os.Environ(), "GOFLAGS=-modcacherw")
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build failed: %w (%s)", err, string(buildOutput))
	}
	return nil
}
