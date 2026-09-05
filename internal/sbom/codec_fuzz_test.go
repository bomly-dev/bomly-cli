package sbom

import (
	"errors"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/spdxkit"
	testkit "github.com/bomly-dev/bomly-sdk/testkit"
)

func FuzzUnmarshalAutoJSON(f *testing.F) {
	for _, seed := range []string{
		`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"demo","documentNamespace":"https://example.com/spdx/demo","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: bomly-fuzz"]},"packages":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`,
		`{"artifacts":[],"artifactRelationships":[],"source":{"type":"directory","target":"."},"descriptor":{"name":"syft","version":"seed"},"schema":{"version":"16.0.34","url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.34.json"}}`,
		// Malformed inputs: rejection paths must be deterministic, never panic.
		``,
		`{}`,
		`null`,
		`[]`,
		`{"hello":"world"}`,
		`{"spdxVersion":"SPDX-9.9"}`,
		`{"bomFormat":"CycloneDX","specVersion":"9.9"}`,
		`{"bomFormat":"CycloneDX","specVersion":1.5}`,
		`{"spdxVersion":"SPDX-2.3","packages":"not-a-list"}`,
		// Truncated documents: valid prefixes cut mid-structure.
		`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"demo","packages":[{"SPDXID":"SPDXRef-`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":`,
		`{"artifacts":[],"schema":{"version":"16.0.34","url":"https://raw.githubusercontent.com/anchore/syft`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > testkit.MaxFuzzInputSize {
			return
		}
		doc, target, err := UnmarshalAutoJSON(raw)

		// Repeated parsing must be deterministic: same success state, same
		// target, and same error classification.
		doc2, target2, err2 := UnmarshalAutoJSON(raw)
		if (err == nil) != (err2 == nil) || target != target2 {
			t.Fatalf("non-deterministic parse: (%q, %v) then (%q, %v)", target, err, target2, err2)
		}
		if err != nil {
			for _, sentinel := range []error{ErrMalformedJSON, ErrUnsupportedFormat} {
				if errors.Is(err, sentinel) != errors.Is(err2, sentinel) {
					t.Fatalf("non-deterministic error classification: %v then %v", err, err2)
				}
			}
		} else if (doc == nil) != (doc2 == nil) {
			t.Fatalf("non-deterministic document presence: %v then %v", doc != nil, doc2 != nil)
		}

		if err != nil {
			return
		}
		if target == "" {
			t.Fatal("successful parse must report a concrete target")
		}
		if doc == nil {
			t.Fatalf("successful %s parse returned nil document", target)
		}
		if _, err := MarshalJSON(doc, target, EncodeOptions{}); err != nil {
			return
		}
	})
}

// FuzzNormalizeSPDXLicenseExpression exercises the license-expression rewriter
// that runs over every component license (detector- and registry-supplied,
// both of which originate in untrusted repository or API data).
func FuzzNormalizeSPDXLicenseExpression(f *testing.F) {
	for _, seed := range []string{
		"MIT",
		"GPL-2.0",
		"GPL-3.0+",
		"(MIT OR GPL-2.0)",
		"LGPL-2.1 WITH Classpath-exception-2.0",
		"Apache-2.0 AND (MIT OR BSD-3-Clause)",
		"",
		"   ",
		"(((",
		")",
		"GPL-2.0-with-classpath-exception",
		"\x00�",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, expression string) {
		if len(expression) > testkit.MaxFuzzInputSize {
			return
		}
		first := normalizeSPDXLicenseExpression(expression)
		if second := normalizeSPDXLicenseExpression(expression); first != second {
			t.Fatalf("nondeterministic normalization: %q vs %q", first, second)
		}
		// Normalization only substitutes identifier tokens; it must never
		// drop expression structure.
		for _, r := range []rune{'(', ')'} {
			if strings.Count(first, string(r)) != strings.Count(expression, string(r)) {
				t.Fatalf("normalization changed %q grouping: %q -> %q", string(r), expression, first)
			}
		}
		if strings.TrimSpace(expression) == "" && first != expression {
			t.Fatalf("blank expression must pass through unchanged: %q -> %q", expression, first)
		}
	})
}

// FuzzSPDXLicenseValue exercises the license classification and composition
// that decides how a license reaches both export formats. The values arrive
// from lockfiles and registry APIs, and classification now runs a third-party
// SPDX expression parser over them, so this guards that path against panics
// and non-determinism.
func FuzzSPDXLicenseValue(f *testing.F) {
	for _, seed := range []string{
		"MIT",
		"mit",
		"Apache-2.0",
		"MIT OR Apache-2.0",
		"Apache-2.0 AND (MIT OR BSD-3-Clause)",
		"GPL-2.0+",
		"LGPL-2.1-only WITH Classpath-exception-2.0",
		"LicenseRef-proprietary",
		"non-standard",
		"see LICENSE file",
		"",
		"   ",
		"(((",
		")",
		"MIT AND",
		"\x00�",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > testkit.MaxFuzzInputSize {
			return
		}

		id, ok := spdxkit.Identifier(value)
		if id2, ok2 := spdxkit.Identifier(value); ok != ok2 || id != id2 {
			t.Fatalf("nondeterministic identifier classification: (%q, %v) then (%q, %v)", id, ok, id2, ok2)
		}
		valid := spdxkit.Valid(value)
		if valid != spdxkit.Valid(value) {
			t.Fatalf("nondeterministic expression validation for %q", value)
		}
		if ok {
			// Anything publishable as a bare `license.id` must also stand on
			// its own as an expression; the two shapes carry the same claim.
			if id == "" {
				t.Fatalf("classified %q as an identifier but returned an empty id", value)
			}
			if !spdxkit.Valid(id) {
				t.Fatalf("identifier %q (from %q) is not a valid expression", id, value)
			}
		}

		// Composition must not lose or reorder members, and must be stable.
		composed := spdxkit.Compose([]string{value, value})
		if composed != spdxkit.Compose([]string{value, value}) {
			t.Fatalf("nondeterministic composition for %q", value)
		}
		if strings.TrimSpace(value) != "" && !strings.Contains(composed, " AND ") {
			t.Fatalf("composition dropped a member: %q -> %q", value, composed)
		}

		// The two encoders read licenses through the same helpers, so neither
		// may panic on any value a source can produce.
		licenses := []License{{Value: value}, {SPDXExpression: value}}
		_ = cycloneDXLicenses(licenses)
		got, extracted := spdxLicenseValue(licenses)
		if got == "" {
			t.Fatalf("spdx license value must never be empty, got %q for %q", got, value)
		}
		// Whatever the value was, the field SPDX will hold has to be
		// something SPDX can hold: an expression, NOASSERTION, or references
		// the document also carries the text for. A free-text value that
		// reached the field verbatim is the defect #410 fixed.
		if got != "NOASSERTION" && !spdxkit.Valid(got) {
			t.Fatalf("license field %q does not parse as an SPDX expression, from %q", got, value)
		}
		for _, entry := range extracted {
			if !entry.Valid() {
				t.Fatalf("minted reference %q does not match its text %q", entry.RefID, entry.Text)
			}
			if !strings.Contains(got, entry.RefID) {
				t.Fatalf("extracted %q is not named by the field %q", entry.RefID, got)
			}
		}
	})
}
