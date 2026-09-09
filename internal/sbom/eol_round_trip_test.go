package sbom

import (
	"strings"
	"testing"
)

// Both formats wrote end-of-life fields that nothing ever read back, so a
// conversion silently dropped a claim the document plainly stated (survey
// defect 4). Each format keeps exactly what it can write: SPDX has no cycle
// field in its package comment, CycloneDX does.
func TestEOLSurvivesADocumentRoundTrip(t *testing.T) {
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX16JSON} {
		t.Run(string(target), func(t *testing.T) {
			doc := &Document{
				Name: "eol",
				Components: []Component{{
					ID:      "pkg:npm/widget@1.0.0",
					Name:    "widget",
					Version: "1.0.0",
					PURL:    "pkg:npm/widget@1.0.0",
					EOL:     &EOL{EOL: true, EOLDate: "2025-01-31", Cycle: "1.x"},
				}},
			}
			raw, err := MarshalJSON(doc, target, EncodeOptions{Pretty: true})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			back, _, err := UnmarshalAutoJSON(raw)
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			got := componentNamed(t, back, "widget").EOL
			if got == nil {
				t.Fatalf("the end-of-life claim was dropped:\n%s", raw)
			}
			if !got.EOL {
				t.Errorf("eol flag = %v, want true", got.EOL)
			}
			if got.EOLDate != "2025-01-31" {
				t.Errorf("eol date = %q, want the source's", got.EOLDate)
			}
			if target == TargetCycloneDX16JSON && got.Cycle != "1.x" {
				t.Errorf("cycle = %q, want the source's -- CycloneDX carries it", got.Cycle)
			}
		})
	}
}

// A date without the flag is not a claim that anything is end-of-life, and an
// unparseable flag is not a reason to guess one.
func TestPartialOrMalformedEOLIsNotInvented(t *testing.T) {
	for _, testCase := range []struct{ name, comment string }{
		{"date without flag", "bomly:eol_date=2025-01-31"},
		{"unparseable flag", "bomly:eol=perhaps;eol_date=2025-01-31"},
		{"no eol fields", "bomly:scope=runtime"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := spdxCommentEOL(testCase.comment); got != nil {
				t.Errorf("invented an end-of-life record from %q: %+v", testCase.comment, got)
			}
		})
	}
}

// Bomly's own export is the only producer of these names, so writer and
// reader have to agree on them; a mismatch writes a field nobody retrieves,
// which is exactly the defect being closed.
func TestEOLPropertyNamesAreSharedByWriterAndReader(t *testing.T) {
	props := cycloneDXEOLProperties(&EOL{EOL: true, EOLDate: "2025-01-31", Cycle: "1.x"})
	if len(props) != 3 {
		t.Fatalf("properties = %+v, want flag, date and cycle", props)
	}
	got := cycloneDXIngestedEOL(&props)
	if got == nil || !got.EOL || got.EOLDate != "2025-01-31" || got.Cycle != "1.x" {
		t.Fatalf("reader did not recover what the writer emitted: %+v", got)
	}
	var names []string
	for _, p := range props {
		names = append(names, p.Name)
	}
	if joined := strings.Join(names, ","); joined != cycloneDXEOLProperty+","+cycloneDXEOLDateProperty+","+cycloneDXEOLCycleProperty {
		t.Errorf("property names = %q", joined)
	}
}
