package sbom

import (
	"errors"
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
			for _, sentinel := range []error{ErrSyftJSONUnsupported, ErrMalformedJSON, ErrUnsupportedFormat} {
				if errors.Is(err, sentinel) != errors.Is(err2, sentinel) {
					t.Fatalf("non-deterministic error classification: %v then %v", err, err2)
				}
			}
		} else if (doc == nil) != (doc2 == nil) {
			t.Fatalf("non-deterministic document presence: %v then %v", doc != nil, doc2 != nil)
		}

		if err != nil {
			if target == TargetSyftJSON && !errors.Is(err, ErrSyftJSONUnsupported) {
				t.Fatalf("syft target must fail with ErrSyftJSONUnsupported, got %v", err)
			}
			return
		}
		if target == TargetSyftJSON {
			t.Fatal("syft target must never parse successfully")
		}
		if doc == nil {
			t.Fatalf("successful %s parse returned nil document", target)
		}
		if _, err := MarshalJSON(doc, target, EncodeOptions{}); err != nil {
			return
		}
	})
}
