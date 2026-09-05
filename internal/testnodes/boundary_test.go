package testnodes_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testnodes builds fixtures and panics when one cannot be built, which is the
// right behaviour for a test and the wrong behaviour for a scan. Nothing
// outside a test file may import it.
//
// A guard rather than a convention: the package is convenient enough that a
// production call site would look reasonable in review, and the failure mode
// -- a panic on a repository whose coordinates the constructor refuses --
// reaches a user rather than a test run.
func TestTestnodesIsImportedOnlyByTests(t *testing.T) {
	const importPath = `"github.com/bomly-dev/bomly-cli/internal/testnodes"`

	roots := []string{"..", filepath.Join("..", "..", "cmd"), filepath.Join("..", "..", "test")}
	var offenders []string
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			source, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(string(source), importPath) {
				offenders = append(offenders, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("internal/testnodes is imported by non-test files: %v", offenders)
	}
}
