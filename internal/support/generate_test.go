package support

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

func TestGenerateConfigReference(t *testing.T) {
	markdown, fieldCount, err := GenerateConfigReference(filepath.Join("..", "cli", "config.go"))
	if err != nil {
		t.Fatalf("generate config reference: %v", err)
	}
	if fieldCount == 0 {
		t.Fatal("expected generated config fields")
	}
	if !strings.Contains(markdown, "| `format` | `BOMLY_FORMAT` | `string` |") {
		t.Fatalf("generated config reference missing format field:\n%s", markdown)
	}
	if !strings.Contains(markdown, "## OSV matcher settings") {
		t.Fatalf("generated config reference missing section heading:\n%s", markdown)
	}
}

func TestGenerateJSONSchemaUsesSharedCommandModels(t *testing.T) {
	schema := GenerateJSONSchema(commandOutputSpecs()[0].typ)
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expected object properties, got %#v", schema)
	}
	if _, ok := properties["manifests"]; !ok {
		t.Fatalf("expected scan schema to expose manifests property: %#v", properties)
	}
	if _, ok := properties["metadata"]; !ok {
		t.Fatalf("expected scan schema to expose metadata property: %#v", properties)
	}
	if commandOutputSpecs()[0].typ != reflect.TypeOf(output.ScanResponse{}) {
		t.Fatal("expected command schema list to use canonical output types")
	}
}

func TestGenerateSchemaReferenceMarkdownIncludesDocumentAndTypes(t *testing.T) {
	markdown := GenerateSchemaReferenceMarkdown("scan", commandOutputSpecs()[0].typ)
	if !strings.Contains(markdown, "## Document") {
		t.Fatalf("schema docs missing document section:\n%s", markdown)
	}
	if !strings.Contains(markdown, "## Types") {
		t.Fatalf("schema docs missing types section:\n%s", markdown)
	}
	if !strings.Contains(markdown, "| `metadata` |") {
		t.Fatalf("schema docs missing metadata field:\n%s", markdown)
	}
}

func TestRenderSupportMatrixMarkdown_DocumentMatches(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "SUPPORT_MATRIX.md"))
	if err != nil {
		t.Fatalf("read support matrix: %v", err)
	}

	got := strings.ReplaceAll(string(data), "\r\n", "\n")
	want := strings.ReplaceAll(RenderSupportMatrixMarkdown(), "\r\n", "\n")
	if got != want {
		t.Fatalf("support matrix document is out of sync with registry\n\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}
