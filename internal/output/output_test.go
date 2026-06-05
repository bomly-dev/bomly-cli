package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestPackageRefMarshalJSONAlwaysIncludesLicenses(t *testing.T) {
	payload, err := json.Marshal(PackageFromGraphPackage(&sdk.Dependency{Name: "react", Version: "18.2.0"}))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !strings.Contains(string(payload), `"licenses":[]`) {
		t.Fatalf("expected empty licenses array, got %s", payload)
	}
}

func TestPackageFromGraphPackageIncludesStructuredLicenses(t *testing.T) {
	dep := &sdk.Dependency{Name: "react", Version: "18.2.0"}
	sdk.SetDetectionLicenses(dep, []sdk.PackageLicense{{
		Value:          "MIT License",
		SPDXExpression: "MIT",
		Type:           "external-depsdev",
	}})
	ref := PackageFromGraphPackage(dep)

	if len(ref.Licenses) != 1 {
		t.Fatalf("expected 1 license, got %#v", ref.Licenses)
	}
	if got := ref.Licenses[0].Identifier(); got != "MIT" {
		t.Fatalf("Identifier() = %q, want %q", got, "MIT")
	}
	if ref.Licenses[0].Type != "external-depsdev" {
		t.Fatalf("unexpected license metadata: %#v", ref.Licenses[0])
	}
}

func TestParseFormatAcceptsSharedFormatsAndAliases(t *testing.T) {
	tests := []struct {
		value string
		want  Format
	}{
		{value: "text", want: FormatText},
		{value: "json", want: FormatJSON},
		{value: "markdown", want: FormatMarkdown},
		{value: "md", want: FormatMarkdown},
		{value: "sarif", want: FormatSARIF},
		{value: "spdx", want: FormatSPDX},
		{value: "spdx-json", want: FormatSPDX},
		{value: "cyclonedx", want: FormatCycloneDX},
		{value: "cyclonedx-json", want: FormatCycloneDX},
		{value: " JSON ", want: FormatJSON},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			format, err := ParseFormat(tc.value)
			if err != nil {
				t.Fatalf("ParseFormat(%q) error = %v", tc.value, err)
			}
			if format != tc.want {
				t.Fatalf("ParseFormat(%q) = %q, want %q", tc.value, format, tc.want)
			}
		})
	}
}
