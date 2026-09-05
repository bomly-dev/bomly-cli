package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/spdxkit"
)

// licenseGraph builds a one-package graph whose licenses a case chooses.
func licenseGraph(t *testing.T, licenses ...sdk.PackageLicense) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	pkg := testnodes.Dep(sdk.Coordinates{Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
	sdk.SetDetectionLicenses(pkg, licenses)
	if _, err := g.InsertNode(pkg); err != nil {
		t.Fatalf("InsertNode: %v", err)
	}
	return g
}

// spdxDocOf marshals a graph to SPDX and decodes the raw document, so a test
// can assert on the fields SPDX defines rather than on our model.
func spdxDocOf(t *testing.T, g *sdk.Graph) map[string]any {
	t.Helper()
	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	return doc
}

// SPDX 2.3 has no free-text license field: licenseDeclared must hold a valid
// expression, NOASSERTION, NONE, or a LicenseRef. Writing "see LICENSE file"
// verbatim produced a document a strict consumer can reject (#410).
func TestUnrecognizedLicenseBecomesAReferenceWithItsText(t *testing.T) {
	const raw = "see LICENSE file"
	doc := spdxDocOf(t, licenseGraph(t, sdk.PackageLicense{Value: raw}))

	packages, _ := doc["packages"].([]any)
	if len(packages) == 0 {
		t.Fatalf("no packages in document")
	}
	pkg, _ := packages[0].(map[string]any)
	declared, _ := pkg["licenseDeclared"].(string)

	want := spdxkit.MintLicenseRef(raw).RefID
	if declared != want {
		t.Fatalf("licenseDeclared = %q, want the minted reference %q", declared, want)
	}
	if declared == raw {
		t.Fatalf("the raw value reached licenseDeclared verbatim")
	}
	if !spdxkit.Valid(declared) {
		t.Fatalf("licenseDeclared %q does not parse as an SPDX expression", declared)
	}

	// And the text travels with it, which is what a reference is for.
	others, _ := doc["hasExtractedLicensingInfos"].([]any)
	if len(others) != 1 {
		t.Fatalf("hasExtractedLicensingInfos = %v, want one entry", others)
	}
	entry, _ := others[0].(map[string]any)
	if got, _ := entry["licenseId"].(string); got != want {
		t.Fatalf("extracted licenseId = %q, want %q", got, want)
	}
	if got, _ := entry["extractedText"].(string); got != raw {
		t.Fatalf("extractedText = %q, want the original %q", got, raw)
	}
}

// A recognized license is untouched: the reference machinery applies only
// where SPDX cannot hold the value.
func TestRecognizedLicenseMintsNoReference(t *testing.T) {
	doc := spdxDocOf(t, licenseGraph(t, sdk.PackageLicense{SPDXExpression: "Apache-2.0"}))
	packages, _ := doc["packages"].([]any)
	pkg, _ := packages[0].(map[string]any)
	if declared, _ := pkg["licenseDeclared"].(string); declared != "Apache-2.0" {
		t.Fatalf("licenseDeclared = %q, want %q", declared, "Apache-2.0")
	}
	if _, present := doc["hasExtractedLicensingInfos"]; present {
		t.Fatalf("a recognized license produced an extracted-text section")
	}
}

// Two components carrying the same unrecognized text mint the same reference
// and collapse to one entry. That is what makes the identifier safe to share
// across a document assembled from independent sources.
func TestIdenticalTextsShareOneReference(t *testing.T) {
	const raw = "internal use only"
	g := sdk.New()
	for _, name := range []string{"alpha", "beta"} {
		pkg := testnodes.Dep(sdk.Coordinates{Ecosystem: "npm", Name: name, Version: "1.0.0"})
		sdk.SetDetectionLicenses(pkg, []sdk.PackageLicense{{Value: raw}})
		if _, err := g.InsertNode(pkg); err != nil {
			t.Fatalf("InsertNode(%s): %v", name, err)
		}
	}
	doc := spdxDocOf(t, g)

	others, _ := doc["hasExtractedLicensingInfos"].([]any)
	if len(others) != 1 {
		t.Fatalf("hasExtractedLicensingInfos has %d entries, want one shared by both packages", len(others))
	}
	want := spdxkit.MintLicenseRef(raw).RefID
	packages, _ := doc["packages"].([]any)
	if len(packages) != 2 {
		t.Fatalf("packages = %d, want two", len(packages))
	}
	for _, p := range packages {
		pkg, _ := p.(map[string]any)
		if declared, _ := pkg["licenseDeclared"].(string); declared != want {
			t.Fatalf("package %v licenseDeclared = %q, want the shared reference %q", pkg["name"], declared, want)
		}
	}
}

// Different texts must not collide, and the identifier must stay inside the
// characters SPDX allows for an idstring.
func TestReferencesAreDistinctAndWellFormed(t *testing.T) {
	first := spdxkit.MintLicenseRef("see LICENSE file")
	second := spdxkit.MintLicenseRef("see COPYING file")
	if first.RefID == second.RefID {
		t.Fatalf("distinct texts minted the same reference %q", first.RefID)
	}
	for _, ref := range []spdxkit.ExtractedText{first, second} {
		if !spdxkit.ValidLicenseRef(ref.RefID) {
			t.Fatalf("reference %q is not a well-formed LicenseRef", ref.RefID)
		}
		if !strings.HasPrefix(ref.RefID, "LicenseRef-") {
			t.Fatalf("reference %q lacks the LicenseRef- prefix", ref.RefID)
		}
	}
	// Deterministic: the same text mints the same reference every time.
	if again := spdxkit.MintLicenseRef("see LICENSE file"); again.RefID != first.RefID {
		t.Fatalf("minting is not deterministic: %q then %q", first.RefID, again.RefID)
	}
}

// Round trip: ingesting the exported document recovers the original text.
// Without this the reference preserves nothing a reader can use — it would
// return "LicenseRef-<hash>" where the source said "see LICENSE file".
func TestReferenceRoundTripRecoversTheOriginalText(t *testing.T) {
	const raw = "see LICENSE file"
	out, err := MarshalDepGraphJSON(licenseGraph(t, sdk.PackageLicense{Value: raw}),
		TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	ingested, err := UnmarshalJSON(out, TargetSPDX23JSON)
	if err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}
	var found bool
	for _, component := range ingested.Components {
		for _, license := range component.Licenses {
			if license.Value == raw {
				found = true
			}
			if license.Value == spdxkit.MintLicenseRef(raw).RefID {
				t.Fatalf("the reference survived as the license value; the text was not read back")
			}
		}
	}
	if !found {
		t.Fatalf("round trip lost the original license text %q: %+v", raw, ingested.Components)
	}
}
