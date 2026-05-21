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

	buildCmd := system.Command("go", "build", "-o", outputPath, srcPath)
	buildCmd.Env = append(os.Environ(), "GOFLAGS=-modcacherw")
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build failed: %w (%s)", err, string(buildOutput))
	}

	return nil
}
