package render

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
)

func TestParseOutputFormatAcceptsSharedFormatsAndAliases(t *testing.T) {
	tests := []struct {
		value      string
		wantFormat output.Format
		wantTarget sbom.Target
		wantLabel  string
	}{
		{value: "text", wantFormat: output.FormatText, wantLabel: "text"},
		{value: "json", wantFormat: output.FormatJSON, wantLabel: "json"},
		{value: "markdown", wantFormat: output.FormatMarkdown, wantLabel: "markdown"},
		{value: "md", wantFormat: output.FormatMarkdown, wantLabel: "markdown"},
		{value: "sarif", wantFormat: output.FormatSARIF, wantLabel: "sarif"},
		{value: "spdx", wantFormat: output.FormatSPDX, wantTarget: sbom.TargetSPDX23JSON, wantLabel: "spdx"},
		{value: "spdx-json", wantFormat: output.FormatSPDX, wantTarget: sbom.TargetSPDX23JSON, wantLabel: "spdx"},
		{value: "cyclonedx", wantFormat: output.FormatCycloneDX, wantTarget: sbom.TargetCycloneDX16JSON, wantLabel: "cyclonedx"},
		{value: "cyclonedx-json", wantFormat: output.FormatCycloneDX, wantTarget: sbom.TargetCycloneDX16JSON, wantLabel: "cyclonedx"},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			format, target, label, err := ParseOutputFormat(tc.value)
			if err != nil {
				t.Fatalf("ParseOutputFormat(%q) error = %v", tc.value, err)
			}
			if format != tc.wantFormat {
				t.Fatalf("format = %q, want %q", format, tc.wantFormat)
			}
			if target != tc.wantTarget {
				t.Fatalf("target = %q, want %q", target, tc.wantTarget)
			}
			if label != tc.wantLabel {
				t.Fatalf("label = %q, want %q", label, tc.wantLabel)
			}
		})
	}
}

func TestParseOutputSpecsParsesReportAndSBOMTargets(t *testing.T) {
	specs, err := ParseOutputSpecs([]string{
		"text=report.txt",
		"json=report.json",
		"md=summary.md",
		"sarif=bomly.sarif",
		"spdx=sbom.spdx.json",
		"cyclonedx=sbom.cdx.json",
	})
	if err != nil {
		t.Fatalf("ParseOutputSpecs() error = %v", err)
	}
	if len(specs) != 6 {
		t.Fatalf("expected 6 specs, got %#v", specs)
	}
	if specs[0].Format != output.FormatText || specs[0].Path != "report.txt" {
		t.Fatalf("unexpected text spec: %#v", specs[0])
	}
	if specs[1].Format != output.FormatJSON || specs[1].Path != "report.json" {
		t.Fatalf("unexpected json spec: %#v", specs[1])
	}
	if specs[2].Format != output.FormatMarkdown || specs[2].Label != "markdown" {
		t.Fatalf("unexpected markdown spec: %#v", specs[2])
	}
	if specs[4].Target != sbom.TargetSPDX23JSON || !specs[4].IsSBOM() {
		t.Fatalf("unexpected spdx spec: %#v", specs[4])
	}
	if specs[5].Target != sbom.TargetCycloneDX16JSON || !specs[5].IsSBOM() {
		t.Fatalf("unexpected cyclonedx spec: %#v", specs[5])
	}
}

func TestParseOutputSpecsRejectsMultipleStdoutTargets(t *testing.T) {
	_, err := ParseOutputSpecs([]string{"json", "spdx"})
	if err == nil {
		t.Fatal("expected multiple stdout outputs to be rejected")
	}
}
