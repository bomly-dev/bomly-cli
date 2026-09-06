package sbom

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// duplicateNameCycloneDX repeats "purl" on one component. Under v1 decoding
// this parses, and which of the two values a consumer reads depends on the Go
// type it decodes into -- so two tools reading this file can disagree about
// what package it names.
const duplicateNameCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "bom-ref": "pkg:npm/widget@1.0.0",
      "type": "library",
      "name": "widget",
      "version": "1.0.0",
      "purl": "pkg:npm/widget@1.0.0",
      "purl": "pkg:npm/evil@1.0.0"
    }
  ]
}`

// A document that reads two ways is refused, and the error names the member.
func TestIngestRejectsDuplicateObjectNames(t *testing.T) {
	_, _, err := UnmarshalAutoJSON([]byte(duplicateNameCycloneDX))
	if !errors.Is(err, ErrAmbiguousJSON) {
		t.Fatalf("err = %v, want %v", err, ErrAmbiguousJSON)
	}
	if !strings.Contains(err.Error(), `"purl"`) {
		t.Errorf("error does not name the repeated member: %v", err)
	}
}

// A nested duplicate is caught too: the check walks the whole document, not
// just its top level.
func TestIngestRejectsNestedDuplicateObjectNames(t *testing.T) {
	raw := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"x",
	  "documentNamespace":"https://example.test/a",
	  "creationInfo":{"created":"2026-01-01T00:00:00Z","created":"2020-01-01T00:00:00Z"}}`
	_, _, err := UnmarshalAutoJSON([]byte(raw))
	if !errors.Is(err, ErrAmbiguousJSON) {
		t.Fatalf("err = %v, want %v", err, ErrAmbiguousJSON)
	}
	if !strings.Contains(err.Error(), "creationInfo") && !strings.Contains(err.Error(), `"created"`) {
		t.Errorf("error does not locate the repeat: %v", err)
	}
}

// Invalid UTF-8 is the same ambiguity class: v1 substitutes U+FFFD, so the
// bytes a consumer sees are not the bytes the document carried.
func TestIngestRejectsInvalidUTF8(t *testing.T) {
	raw := "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1," +
		"\"components\":[{\"bom-ref\":\"a\",\"type\":\"library\",\"name\":\"wi\xffdget\"}]}"
	_, _, err := UnmarshalAutoJSON([]byte(raw))
	if !errors.Is(err, ErrAmbiguousJSON) {
		t.Fatalf("err = %v, want %v", err, ErrAmbiguousJSON)
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error does not say what was wrong: %v", err)
	}
}

// The rejection is bounded to those two classes. A document that is merely
// unusual -- unknown members, deep nesting, an empty component list -- still
// parses, because tightening beyond the stated guarantee would reject
// documents whose meaning was never in doubt.
func TestStrictIngestDoesNotRejectMerelyUnusualDocuments(t *testing.T) {
	raw := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "someUnknownMember": {"deeply": {"nested": [1, 2, {"and": "fine"}]}},
  "components": []
}`
	if _, _, err := UnmarshalAutoJSON([]byte(raw)); err != nil {
		t.Fatalf("a well-formed document was rejected: %v", err)
	}
}

// Bomly's own output always passes its own gate, in both formats. A gate that
// rejected what the encoder writes would be a released defect, not a defense.
func TestBomlyOutputPassesTheStrictGate(t *testing.T) {
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX16JSON} {
		t.Run(string(target), func(t *testing.T) {
			raw, err := MarshalDepGraphJSON(scopedGraph(t, "runtime"), target, BuildOptions{}, EncodeOptions{Pretty: true})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			if err := requireUnambiguousJSON(raw); err != nil {
				t.Fatalf("Bomly's own output fails the gate: %v", err)
			}
		})
	}
}

// The format is read out of the document, so a document that repeats its own
// discriminator is ambiguous about which format it even claims to be. Sniffing
// before checking reported an unsupported format instead -- the one input where
// the ambiguity error is most worth having.
func TestAmbiguityIsReportedBeforeFormatDetection(t *testing.T) {
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[],"bomFormat":"other"}`
	_, _, err := UnmarshalAutoJSON([]byte(raw))
	if !errors.Is(err, ErrAmbiguousJSON) {
		t.Fatalf("err = %v, want %v", err, ErrAmbiguousJSON)
	}
	if errors.Is(err, ErrUnsupportedFormat) {
		t.Error("the repeated discriminator was reported as an unsupported format")
	}
	if !strings.Contains(err.Error(), "bomFormat") {
		t.Errorf("error does not name the repeated discriminator: %v", err)
	}
}

// A malformed document is still reported as malformed. The strict pass runs
// first now, and wrapping every reader error as "ambiguous" would send someone
// hunting for a repeated member in a file that is merely truncated.
func TestMalformedDocumentsAreNotReportedAsAmbiguous(t *testing.T) {
	for _, raw := range []string{`{"hello"`, `not json at all`, `{"a":`} {
		_, _, err := UnmarshalAutoJSON([]byte(raw))
		if !errors.Is(err, ErrMalformedJSON) {
			t.Errorf("%q: err = %v, want %v", raw, err, ErrMalformedJSON)
		}
		if errors.Is(err, ErrAmbiguousJSON) {
			t.Errorf("%q: a malformed document was reported as ambiguous", raw)
		}
	}
}

// A document too large to check is refused rather than waved through, whether
// its names sit in one object or are spread across nested ones.
//
// Detecting a repeated name costs memory in proportion to the names held at
// once, so a document can otherwise make the check itself the denial of
// service -- and skipping the check on the largest inputs would put the hole
// where a payload would go.
func TestADocumentTooLargeToCheckIsRefused(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"wide":{`)
	for i := range maxOpenObjectMembers + 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"k%d":1`, i)
	}
	b.WriteString("}}")

	_, _, err := UnmarshalAutoJSON([]byte(b.String()))
	if !errors.Is(err, ErrUnverifiableJSON) {
		t.Fatalf("err = %v, want %v", err, ErrUnverifiableJSON)
	}
	if !strings.Contains(err.Error(), "open at once") {
		t.Errorf("error does not say what the problem is: %v", err)
	}
}

// Names spread across nested objects count too. Each level here is well under
// the bound on its own, but every level stays open until the last one closes,
// so their names are all held at once -- and bounding only the widest single
// object accepted this shape while it drove the checker into gigabytes.
func TestNestedObjectsCannotAccumulatePastTheBound(t *testing.T) {
	const levels = 40
	perLevel := maxOpenObjectMembers/levels + 100

	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"x":`)
	for level := range levels {
		b.WriteByte('{')
		for i := range perLevel {
			fmt.Fprintf(&b, `"k%d_%d":1,`, level, i)
		}
		b.WriteString(`"next":`)
	}
	b.WriteString("null")
	for range levels {
		b.WriteByte('}')
	}
	b.WriteByte('}')

	_, _, err := UnmarshalAutoJSON([]byte(b.String()))
	if !errors.Is(err, ErrUnverifiableJSON) {
		t.Fatalf("err = %v, want %v -- no single object exceeds the bound, but together they do", err, ErrUnverifiableJSON)
	}
}

// Closing an object releases its names, so a document that is merely long --
// many sibling objects, one after another -- is not refused. Without that, the
// bound would count every object a file ever contained instead of the ones
// open at once.
func TestSiblingObjectsDoNotAccumulate(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[`)
	for i := range 200 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"bom-ref":"r`)
		fmt.Fprintf(&b, `%d","type":"library","name":"p%d","version":"1.0.0","purl":"pkg:npm/p%d@1.0.0","properties":[`, i, i, i)
		// Each component carries a wide-ish property object that closes again.
		for j := range 2_000 {
			if j > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"name":"n%d","value":"v"}`, j)
		}
		b.WriteString(`]}`)
	}
	b.WriteString("]}")

	if _, _, err := UnmarshalAutoJSON([]byte(b.String())); err != nil {
		t.Fatalf("a long document whose objects close was refused: %v", err)
	}
}

// The bound has room for documents that are merely large. A real SBOM's widest
// object is a component; the limit is orders of magnitude above that, and a
// document with many components must not trip it.
func TestManyComponentsDoNotTripTheWidthBound(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[`)
	for i := range 20_000 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"bom-ref":"pkg:npm/p%d@1.0.0","type":"library","name":"p%d","version":"1.0.0","purl":"pkg:npm/p%d@1.0.0"}`, i, i, i)
	}
	b.WriteString("]}")

	doc, _, err := UnmarshalAutoJSON([]byte(b.String()))
	if err != nil {
		t.Fatalf("a large but ordinary document was refused: %v", err)
	}
	if len(doc.Components) != 20_000 {
		t.Errorf("components = %d", len(doc.Components))
	}
}

// Long member names are refused on their bytes even when their count is
// inside the other bound.
//
// A count is not a size: 99,000 two-kilobyte names sit under the count limit
// and still weigh ~194 MiB, which is legal input under the 256 MiB file limit
// and drove retention to 900 MiB before this bound existed.
func TestLongMemberNamesAreBoundedByTheirBytes(t *testing.T) {
	// Well inside the count bound, deliberately: the count must not be what
	// rejects this, or the test would pass without the byte bound.
	const names = 2_000
	const nameLength = 16 << 10

	pad := strings.Repeat("p", nameLength)
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"wide":{`)
	for i := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"%s%d":1`, pad, i)
	}
	b.WriteString("}}")

	if names > maxOpenObjectMembers {
		t.Fatalf("the fixture trips the count bound (%d names), so it would pass without the byte bound", names)
	}
	_, _, err := UnmarshalAutoJSON([]byte(b.String()))
	if !errors.Is(err, ErrUnverifiableJSON) {
		t.Fatalf("err = %v, want %v", err, ErrUnverifiableJSON)
	}
	if !strings.Contains(err.Error(), "bytes") {
		t.Errorf("the error does not say the byte bound fired: %v", err)
	}
}

// Closing an object releases its name bytes as well as its count.
//
// This document's names total far more than the byte bound, but only one
// object's worth is ever open at a time, so it must be accepted. Without the
// release it is refused -- which would reject long, ordinary documents rather
// than pathological ones.
func TestClosedObjectsReleaseTheirNameBytes(t *testing.T) {
	const objects = 20_000
	const nameLength = 2048
	pad := strings.Repeat("p", nameLength)

	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"x":[`)
	for i := range objects {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"%s%d":1}`, pad, i)
	}
	b.WriteString("]}")

	if cumulative := int64(objects) * nameLength; cumulative <= maxOpenNameBytes {
		t.Fatalf("the fixture's %d cumulative name bytes are inside the bound, so it would pass without the release", cumulative)
	}
	if _, _, err := UnmarshalAutoJSON([]byte(b.String())); err != nil {
		t.Fatalf("a document whose objects close was refused: %v", err)
	}
}

// Ordinary member names are nowhere near the byte bound. Both formats use
// spec-defined field names of tens of bytes, so a document with many
// components must not trip it.
func TestOrdinaryNamesDoNotApproachTheByteBound(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[`)
	for i := range 5_000 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"bom-ref":"pkg:npm/p%d@1.0.0","type":"library","name":"p%d","version":"1.0.0","purl":"pkg:npm/p%d@1.0.0"}`, i, i, i)
	}
	b.WriteString("]}")

	if _, _, err := UnmarshalAutoJSON([]byte(b.String())); err != nil {
		t.Fatalf("an ordinary document was refused: %v", err)
	}
}
