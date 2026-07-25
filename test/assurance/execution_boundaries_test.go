package assurance

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestReadOnlyRemediationSourcesDoNotImportExecutionOrIOPackages(t *testing.T) {
	root := repositoryRoot(t)
	files := []string{
		filepath.Join(root, "internal", "remediation", "derive.go"),
		filepath.Join(root, "internal", "detectors", "remediation.go"),
	}
	err := filepath.WalkDir(filepath.Join(root, "internal", "detectors"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() != "remediation.go" {
			return nil
		}
		if path != files[1] {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk detector remediation sources: %v", err)
	}

	forbidden := map[string]string{
		"net":      "network access",
		"net/http": "network access",
		"os":       "filesystem or process environment access",
		"os/exec":  "subprocess execution",
		"github.com/bomly-dev/bomly-cli/internal/system":         "filesystem or subprocess access",
		"github.com/bomly-dev/bomly-cli/internal/matchers/cache": "cache filesystem access",
	}
	for _, path := range files {
		path := path
		t.Run(strings.TrimPrefix(path, root+string(filepath.Separator)), func(t *testing.T) {
			file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if parseErr != nil {
				t.Fatalf("parse imports: %v", parseErr)
			}
			for _, imported := range file.Imports {
				name, unquoteErr := strconv.Unquote(imported.Path.Value)
				if unquoteErr != nil {
					t.Fatalf("decode import %q: %v", imported.Path.Value, unquoteErr)
				}
				if reason, found := forbidden[name]; found {
					t.Errorf("read-only remediation source imports %q, which permits %s", name, reason)
				}
			}
		})
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve assurance test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}
