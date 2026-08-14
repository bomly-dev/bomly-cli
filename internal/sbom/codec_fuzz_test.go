package sbom

import (
	"errors"
	"strings"
	"testing"

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
