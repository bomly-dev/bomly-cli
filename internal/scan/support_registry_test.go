package scan

import (
	"os"
	"strings"
	"testing"
)

func TestRenderSupportMatrixMarkdown_DocumentMatches(t *testing.T) {
	data, err := os.ReadFile("../../docs/SUPPORT_MATRIX.md")
	if err != nil {
		t.Fatalf("read support matrix: %v", err)
	}

	got := strings.ReplaceAll(string(data), "\r\n", "\n")
	want := strings.ReplaceAll(RenderSupportMatrixMarkdown(), "\r\n", "\n")
	if got != want {
		t.Fatalf("support matrix document is out of sync with registry\n\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}
