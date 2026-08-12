package assurance

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const unboundedReadAllowance = "assurance:allow-unbounded-read"

var unboundedWholeFileReadCalls = []string{
	"os.ReadFile(",
	"ioutil.ReadFile(",
	"io.ReadAll(",
}

func TestRepositoryParsersDoNotUseUnboundedWholeFileReads(t *testing.T) {
	root := assuranceRepositoryRoot(t)
	for _, relativeRoot := range []string{
		"components/analyzers",
		"internal/detectors",
		"internal/registry",
	} {
		if err := inspectRepositorySourceDirectory(t, root, relativeRoot); err != nil {
			t.Fatalf("inspect %s: %v", relativeRoot, err)
		}
	}
	for _, relativePath := range []string{
		"internal/benchmark/targets.go",
	} {
		if err := inspectRepositorySourceFile(t, root, relativePath); err != nil {
			t.Fatalf("inspect %s: %v", relativePath, err)
		}
	}
}

func inspectRepositorySourceDirectory(t *testing.T, root, relativeRoot string) error {
	t.Helper()
	searchRoot := filepath.Join(root, filepath.FromSlash(relativeRoot))
	return filepath.WalkDir(searchRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			relative = path
		}
		return inspectRepositorySource(t, path, filepath.ToSlash(relative))
	})
}

func inspectRepositorySourceFile(t *testing.T, root, relativePath string) error {
	t.Helper()
	return inspectRepositorySource(t, filepath.Join(root, filepath.FromSlash(relativePath)), relativePath)
}

func inspectRepositorySource(t *testing.T, path, displayPath string) error {
	t.Helper()
	source, err := os.ReadFile(path) // #nosec G304 -- fixed repository source path used only by this test
	if err != nil {
		return err
	}
	for _, violation := range unboundedReadViolations(string(source)) {
		t.Errorf("%s:%d uses %s; repository parser inputs must use a bounded system reader", displayPath, violation.line, violation.call)
	}
	return nil
}

type unboundedReadViolation struct {
	line int
	call string
}

func unboundedReadViolations(source string) []unboundedReadViolation {
	lines := strings.Split(source, "\n")
	violations := make([]unboundedReadViolation, 0)
	for index, line := range lines {
		for _, call := range unboundedWholeFileReadCalls {
			if !strings.Contains(line, call) {
				continue
			}
			if hasUnboundedReadAllowance(lines, index) {
				continue
			}
			violations = append(violations, unboundedReadViolation{line: index + 1, call: call})
		}
	}
	return violations
}

func hasUnboundedReadAllowance(lines []string, index int) bool {
	for _, candidate := range []int{index, index - 1} {
		if candidate < 0 {
			continue
		}
		marker := strings.Index(lines[candidate], unboundedReadAllowance)
		if marker < 0 {
			continue
		}
		if strings.TrimSpace(lines[candidate][marker+len(unboundedReadAllowance):]) != "" {
			return true
		}
	}
	return false
}

func TestUnboundedReadViolationsRequireDocumentedAllowance(t *testing.T) {
	source := fmt.Sprintf(`package fixture

func unbounded() {
	_, _ = os.ReadFile("one")
	_, _ = io.ReadAll(reader) // %s generated parser owns an independent 1 MiB limit
	// %s standard library decoder enforces the configured archive limit
	_, _ = ioutil.ReadFile("two")
}
`, unboundedReadAllowance, unboundedReadAllowance)
	violations := unboundedReadViolations(source)
	if len(violations) != 1 || violations[0].call != "os.ReadFile(" {
		t.Fatalf("unboundedReadViolations() = %#v, want only os.ReadFile violation", violations)
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
