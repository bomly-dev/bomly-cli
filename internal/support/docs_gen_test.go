package support

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateDocsWritesAllArtifacts(t *testing.T) {
	tmp := t.TempDir()
	lines, err := GenerateDocs(tmp)
	if err != nil {
		t.Fatalf("generate docs: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("expected summary lines")
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "generated ") {
			t.Fatalf("unexpected summary line %q", line)
		}
	}

	for _, path := range []string{
		filepath.Join(tmp, "CONFIG_REFERENCE.md"),
		filepath.Join(tmp, "SUPPORT_MATRIX.md"),
		filepath.Join(tmp, "schemas", "scan.schema.json"),
		filepath.Join(tmp, "schemas", "diff.schema.json"),
		filepath.Join(tmp, "schemas", "explain.schema.json"),
		filepath.Join(tmp, "schemas", "scan.md"),
		filepath.Join(tmp, "schemas", "diff.md"),
		filepath.Join(tmp, "schemas", "explain.md"),
		filepath.Join(tmp, "DETECTORS.md"),
		filepath.Join(tmp, "MATCHERS.md"),
		filepath.Join(tmp, "AUDITORS.md"),
		filepath.Join(tmp, "detectors", "README.md"),
		filepath.Join(tmp, "detectors", "go", "gomod.md"),
		filepath.Join(tmp, "detectors", "npm", "npm.md"),
		filepath.Join(tmp, "detectors", "npm", "pnpm.md"),
		filepath.Join(tmp, "detectors", "npm", "yarn.md"),
		filepath.Join(tmp, "detectors", "python", "pip.md"),
		filepath.Join(tmp, "detectors", "syft.md"),
		filepath.Join(tmp, "matchers", "osv.md"),
		filepath.Join(tmp, "auditors", "README.md"),
		filepath.Join(tmp, "auditors", "vulnerability.md"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected generated doc %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Fatalf("generated doc %s is empty", path)
		}
	}

	content, err := os.ReadFile(filepath.Join(tmp, "CONFIG_REFERENCE.md"))
	if err != nil {
		t.Fatalf("read config reference: %v", err)
	}
	if !strings.Contains(string(content), "| `output.format` |") {
		t.Fatalf("config reference generated from embedded source missing format field:\n%s", content)
	}
}

func TestGenerateDocsIsDeterministic(t *testing.T) {
	firstDir := t.TempDir()
	secondDir := t.TempDir()
	first, err := GenerateDocs(firstDir)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	second, err := GenerateDocs(secondDir)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("summary line count differs: %d vs %d", len(first), len(second))
	}
	for idx := range first {
		normalizedFirst := strings.ReplaceAll(first[idx], firstDir, "DOCS")
		normalizedSecond := strings.ReplaceAll(second[idx], secondDir, "DOCS")
		if normalizedFirst != normalizedSecond {
			t.Fatalf("summary order differs at %d: %q vs %q", idx, normalizedFirst, normalizedSecond)
		}
	}
}
