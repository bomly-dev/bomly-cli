package assurance

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryParsersDoNotUseUnboundedWholeFileReads(t *testing.T) {
	root := assuranceRepositoryRoot(t)
	for _, relativeRoot := range []string{
		"internal/analyzers",
		"internal/detectors",
		"internal/registry",
	} {
		searchRoot := filepath.Join(root, filepath.FromSlash(relativeRoot))
		err := filepath.WalkDir(searchRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			source, err := os.ReadFile(path) // #nosec G304 -- fixed repository source path used only by this test
			if err != nil {
				return err
			}
			if strings.Contains(string(source), "os.ReadFile(") {
				relative, relErr := filepath.Rel(root, path)
				if relErr != nil {
					relative = path
				}
				t.Errorf("%s uses os.ReadFile; repository parser inputs must use system.ReadRepositoryFile", filepath.ToSlash(relative))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("inspect %s: %v", relativeRoot, err)
		}
	}
}

func assuranceRepositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}
