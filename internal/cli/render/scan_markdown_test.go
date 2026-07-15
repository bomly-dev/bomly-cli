package render

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

func TestScanMarkdownDedupsSharedModuleDependencies(t *testing.T) {
	shared := output.ScanDependency{ID: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21"}
	payload := output.ScanResponse{
		Manifests: []output.ScanManifest{
			{Path: "package-lock.json", Subproject: ".", Dependencies: []output.ScanDependency{shared}},
			{Path: "apps/web/package.json", Subproject: ".", Dependencies: []output.ScanDependency{shared}},
		},
	}
	var b strings.Builder
	if err := ScanMarkdown(&b, payload); err != nil {
		t.Fatalf("ScanMarkdown() error = %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "- Packages: 1") {
		t.Fatalf("expected deduped package count of 1, got:\n%s", out)
	}
	if strings.Count(out, "lodash@4.17.21") != 1 {
		t.Fatalf("expected shared dependency listed once in inventory, got:\n%s", out)
	}
	if !strings.Contains(out, "apps/web (module)") {
		t.Fatalf("expected module location cell in manifest table, got:\n%s", out)
	}
}
