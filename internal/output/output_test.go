package output

import (
	"encoding/json"
	"strings"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestPackageRefMarshalJSONAlwaysIncludesLicenses(t *testing.T) {
	payload, err := json.Marshal(PackageFromGraphPackage(&model.Package{Name: "react", Version: "18.2.0"}))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !strings.Contains(string(payload), `"licenses":[]`) {
		t.Fatalf("expected empty licenses array, got %s", payload)
	}
}

func TestPackageFromGraphPackageIncludesStructuredLicenses(t *testing.T) {
	ref := PackageFromGraphPackage(&model.Package{
		Name:    "react",
		Version: "18.2.0",
		Licenses: []model.PackageLicense{{
			Value:          "MIT License",
			SPDXExpression: "MIT",
			Type:           "external-depsdev",
		}},
	})

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
