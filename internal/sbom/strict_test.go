package sbom

import (
	"errors"
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
