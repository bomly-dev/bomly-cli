package sbom

import (
	"bytes"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/spdxkit"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// licensedGraph builds a one-node graph whose single component declares the
// given licenses at detection time.
func licensedGraph(t *testing.T, licenses ...sdk.PackageLicense) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	dep := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
		Name:      "left-pad",
		Version:   "1.3.0",
		PURL:      "pkg:npm/left-pad@1.3.0",
		Ecosystem: "npm",
	}})
	sdk.SetDetectionLicenses(dep, licenses)
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add node: %v", err)
	}
	return g
}

func cycloneDXComponentLicenses(t *testing.T, g *sdk.Graph) cdx.Licenses {
	t.Helper()
	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		t.Fatalf("decode cyclonedx: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("expected exactly 1 component, got %#v", bom.Components)
	}
	comp := (*bom.Components)[0]
	if comp.Licenses == nil {
		return nil
	}
	return *comp.Licenses
}

func spdxPackageLicense(t *testing.T, g *sdk.Graph) *v23.Package {
	t.Helper()
	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("decode spdx: %v", err)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("expected exactly 1 package, got %d", len(doc.Packages))
	}
	return doc.Packages[0]
}

// TestCycloneDXLicenseShapes pins how each kind of license value is published.
// A recognized identifier must reach `license.id` (a checked SPDX list entry),
// a compound value must reach `expression`, and only genuinely unrecognized
// text may fall through to the free-text `license.name`.
func TestCycloneDXLicenseShapes(t *testing.T) {
	tests := []struct {
		name       string
		licenses   []sdk.PackageLicense
		wantID     string
		wantExpr   string
		wantName   string
		wantLength int
	}{
		{
			name:       "plain identifier becomes license.id",
			licenses:   []sdk.PackageLicense{{Value: "MIT"}},
			wantID:     "MIT",
			wantLength: 1,
		},
		{
			name:       "identifier casing is canonicalized",
			licenses:   []sdk.PackageLicense{{Value: "mit"}},
			wantID:     "MIT",
			wantLength: 1,
		},
		{
			name:       "compound value stays an expression",
			licenses:   []sdk.PackageLicense{{SPDXExpression: "MIT OR Apache-2.0"}},
			wantExpr:   "MIT OR Apache-2.0",
			wantLength: 1,
		},
		{
			name:       "or-later operator stays an expression",
			licenses:   []sdk.PackageLicense{{SPDXExpression: "LGPL-2.1-only+"}},
			wantExpr:   "LGPL-2.1-only+",
			wantLength: 1,
		},
		{
			name:       "unrecognized text stays free text",
			licenses:   []sdk.PackageLicense{{Value: "see LICENSE file"}},
			wantName:   "see LICENSE file",
			wantLength: 1,
		},
		{
			// Registry sources write free text into the same field they write
			// real expressions into. Publishing it as `expression` produced a
			// document that fails CycloneDX expression validation.
			name:       "unrecognized expression is demoted to free text",
			licenses:   []sdk.PackageLicense{{Value: "non-standard", SPDXExpression: "non-standard"}},
			wantName:   "non-standard",
			wantLength: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			licenses := cycloneDXComponentLicenses(t, licensedGraph(t, tc.licenses...))
			if len(licenses) != tc.wantLength {
				t.Fatalf("expected %d license entries, got %#v", tc.wantLength, licenses)
			}
			got := licenses[0]
			switch {
			case tc.wantID != "":
				if got.License == nil || got.License.ID != tc.wantID {
					t.Fatalf("expected license.id %q, got %#v", tc.wantID, got)
				}
				if got.License.Name != "" {
					t.Fatalf("expected no free-text name alongside an id, got %q", got.License.Name)
				}
			case tc.wantExpr != "":
				if got.Expression != tc.wantExpr {
					t.Fatalf("expected expression %q, got %#v", tc.wantExpr, got)
				}
			case tc.wantName != "":
				if got.License == nil || got.License.Name != tc.wantName {
					t.Fatalf("expected license.name %q, got %#v", tc.wantName, got)
				}
				if got.License.ID != "" {
					t.Fatalf("expected no id for unrecognized text, got %q", got.License.ID)
				}
				if got.Expression != "" {
					t.Fatalf("expected no expression for unrecognized text, got %q", got.Expression)
				}
			}
		})
	}
}

// TestCycloneDXMultipleLicenses covers the format's either/or rule: a license
// list holds license objects or one expression, never a mix and never two
// expressions.
func TestCycloneDXMultipleLicenses(t *testing.T) {
	// Listing several licenses says only that they were found. Composing them
	// with AND would claim a package offered under either is bound by both.
	t.Run("several identifiers are listed, not composed", func(t *testing.T) {
		licenses := cycloneDXComponentLicenses(t, licensedGraph(t,
			sdk.PackageLicense{Value: "MIT"},
			sdk.PackageLicense{Value: "Apache-2.0"},
		))
		if len(licenses) != 2 {
			t.Fatalf("expected 2 license entries, got %#v", licenses)
		}
		for i, want := range []string{"MIT", "Apache-2.0"} {
			if licenses[i].License == nil || licenses[i].License.ID != want {
				t.Fatalf("expected license.id %q at %d, got %#v", want, i, licenses[i])
			}
			if licenses[i].Expression != "" {
				t.Fatalf("expected no asserted relationship, got %q", licenses[i].Expression)
			}
		}
	})

	// A list cannot mix objects with an expression, and an object cannot hold
	// one, so a compound member leaves composition as the only way to keep it.
	t.Run("a compound member forces composition", func(t *testing.T) {
		licenses := cycloneDXComponentLicenses(t, licensedGraph(t,
			sdk.PackageLicense{SPDXExpression: "Apache-2.0 OR MIT"},
			sdk.PackageLicense{Value: "Unicode-DFS-2016"},
		))
		if len(licenses) != 1 {
			t.Fatalf("expected a single composed entry, got %#v", licenses)
		}
		if licenses[0].Expression != "(Apache-2.0 OR MIT) AND Unicode-DFS-2016" {
			t.Fatalf("expected the compound member preserved, got %#v", licenses[0])
		}
	})

	t.Run("mixed validity falls back to per-license objects", func(t *testing.T) {
		licenses := cycloneDXComponentLicenses(t, licensedGraph(t,
			sdk.PackageLicense{Value: "MIT"},
			sdk.PackageLicense{Value: "non-standard"},
		))
		if len(licenses) != 2 {
			t.Fatalf("expected 2 license entries, got %#v", licenses)
		}
		if licenses[0].License == nil || licenses[0].License.ID != "MIT" {
			t.Fatalf("expected the recognized license to keep its id, got %#v", licenses[0])
		}
		if licenses[1].License == nil || licenses[1].License.Name != "non-standard" {
			t.Fatalf("expected the unrecognized license as free text, got %#v", licenses[1])
		}
		for _, l := range licenses {
			if l.Expression != "" {
				t.Fatalf("expected no expression when emitting license objects, got %#v", l)
			}
		}
	})
}

// TestSPDXLicenseComposition covers SPDX 2.3 holding one expression per
// package: several declared licenses must compose rather than lose all but the
// first.
func TestSPDXLicenseComposition(t *testing.T) {
	tests := []struct {
		name     string
		licenses []sdk.PackageLicense
		want     string
	}{
		{
			name: "no licenses",
			want: "NOASSERTION",
		},
		{
			name:     "single value passes through",
			licenses: []sdk.PackageLicense{{Value: "MIT"}},
			want:     "MIT",
		},
		{
			name: "multiple licenses compose with AND",
			licenses: []sdk.PackageLicense{
				{Value: "MIT"},
				{Value: "Apache-2.0"},
			},
			want: "MIT AND Apache-2.0",
		},
		{
			name: "compound elements are parenthesized",
			licenses: []sdk.PackageLicense{
				{Value: "MIT"},
				{SPDXExpression: "MIT OR GPL-2.0-only"},
			},
			want: "MIT AND (MIT OR GPL-2.0-only)",
		},
		{
			// A mixed set composes fully now (#410). The unrecognized member
			// becomes a reference, which is a valid expression element, so
			// nothing is dropped -- this used to keep "MIT" alone and lose
			// the fact that a second license was declared at all.
			name: "an unrecognized member composes as a reference",
			licenses: []sdk.PackageLicense{
				{Value: "MIT"},
				{Value: "non-standard"},
			},
			want: "MIT AND " + spdxkit.MintLicenseRef("non-standard").RefID,
		},
		{
			// A lone unrecognized value is a reference rather than free text
			// in a field SPDX says must hold an expression.
			name: "a single unrecognized value becomes a reference",
			licenses: []sdk.PackageLicense{
				{Value: "see LICENSE file"},
			},
			want: spdxkit.MintLicenseRef("see LICENSE file").RefID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkg := spdxPackageLicense(t, licensedGraph(t, tc.licenses...))
			if pkg.PackageLicenseDeclared != tc.want {
				t.Fatalf("declared: expected %q, got %q", tc.want, pkg.PackageLicenseDeclared)
			}
		})
	}
}

// TestSPDXLicenseConcludedIsNeverAsserted pins that Bomly does not conclude a
// license. Concluded is the document creator's own determination; every
// license Bomly holds is declared by a source, and Bomly analyzes no package
// contents, so SPDX's NOASSERTION is the honest value. The declared field
// still carries what the source said.
func TestSPDXLicenseConcludedIsNeverAsserted(t *testing.T) {
	for _, licenses := range [][]sdk.PackageLicense{
		nil,
		{{Value: "MIT"}},
		{{SPDXExpression: "MIT OR Apache-2.0"}},
		{{Value: "MIT"}, {Value: "Apache-2.0"}},
		{{Value: "see LICENSE file"}},
	} {
		pkg := spdxPackageLicense(t, licensedGraph(t, licenses...))
		if pkg.PackageLicenseConcluded != "NOASSERTION" {
			t.Fatalf("expected NOASSERTION concluded for %#v, got %q", licenses, pkg.PackageLicenseConcluded)
		}
	}
}

// TestSPDXConcludedNoAssertionSurvivesIngest covers the round trip: a document
// whose concluded field is NOASSERTION must still yield the declared license
// when read back, not a literal "NOASSERTION" license.
func TestSPDXConcludedNoAssertionSurvivesIngest(t *testing.T) {
	out, err := MarshalDepGraphJSON(licensedGraph(t, sdk.PackageLicense{Value: "MIT"}),
		TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	doc, _, err := UnmarshalAutoJSON(out)
	if err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(doc.Components))
	}
	licenses := doc.Components[0].Licenses
	if len(licenses) != 1 || licenses[0].Value != "MIT" {
		t.Fatalf("expected the declared MIT license to survive ingest, got %#v", licenses)
	}
}

// TestSourceStatedRelationshipSurvivesBothFormats covers the case that
// actually matters for dual licensing: when a source states the relationship
// itself ("Apache-2.0 OR MIT", how registries record it), both formats publish
// that expression unchanged rather than reinterpreting it.
func TestSourceStatedRelationshipSurvivesBothFormats(t *testing.T) {
	const expression = "Apache-2.0 OR MIT"
	licenses := []sdk.PackageLicense{{SPDXExpression: expression}}

	cdxLicenses := cycloneDXComponentLicenses(t, licensedGraph(t, licenses...))
	if len(cdxLicenses) != 1 || cdxLicenses[0].Expression != expression {
		t.Fatalf("cyclonedx changed a source-stated expression: %#v", cdxLicenses)
	}
	if got := spdxPackageLicense(t, licensedGraph(t, licenses...)).PackageLicenseDeclared; got != expression {
		t.Fatalf("spdx changed a source-stated expression: %q", got)
	}
}

// TestMultipleLicensesDivergeByFormat pins the one deliberate cross-format
// difference. CycloneDX can list licenses without relating them; SPDX 2.3
// holds a single expression and has no such form, so it must compose. Both are
// the most faithful thing each format can say.
func TestMultipleLicensesDivergeByFormat(t *testing.T) {
	licenses := []sdk.PackageLicense{{Value: "MIT"}, {Value: "Apache-2.0"}}

	cdxLicenses := cycloneDXComponentLicenses(t, licensedGraph(t, licenses...))
	if len(cdxLicenses) != 2 {
		t.Fatalf("expected CycloneDX to list both licenses, got %#v", cdxLicenses)
	}
	if got := spdxPackageLicense(t, licensedGraph(t, licenses...)).PackageLicenseDeclared; got != "MIT AND Apache-2.0" {
		t.Fatalf("expected SPDX to compose, got %q", got)
	}
}
