package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInternalCommandIsHiddenFromRootHelp(t *testing.T) {
	root, err := newRootCmd("test")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "internal") {
		t.Fatalf("root help exposed hidden internal command:\n%s", out.String())
	}
	cmd, _, err := root.Find([]string{"internal", "docs-gen"})
	if err != nil || cmd == nil || cmd.Name() != "docs-gen" {
		t.Fatalf("root.Find(internal docs-gen) = %#v, %v", cmd, err)
	}
}

func TestInternalDocsGenWritesArtifactsAndSummary(t *testing.T) {
	root, err := newRootCmd("test")
	if err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(t.TempDir(), "docs")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"internal", "docs-gen", "--output", outputDir})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(outputDir, "CONFIG_REFERENCE.md"),
		filepath.Join(outputDir, "SUPPORT_MATRIX.md"),
		filepath.Join(outputDir, "schemas", "scan.schema.json"),
		filepath.Join(outputDir, "DETECTORS.md"),
		filepath.Join(outputDir, "detectors", "README.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated doc %s: %v", path, err)
		}
	}
	if !strings.Contains(out.String(), "generated "+filepath.Join(outputDir, "CONFIG_REFERENCE.md")) {
		t.Fatalf("docs-gen summary missing config reference line:\n%s", out.String())
	}
}
