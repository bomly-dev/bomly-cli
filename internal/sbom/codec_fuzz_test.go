package sbom

import (
	"errors"
	"testing"
)

const maxFuzzInputSize = 1 << 20

func FuzzUnmarshalAutoJSON(f *testing.F) {
	for _, seed := range []string{
		`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"demo","documentNamespace":"https://example.com/spdx/demo","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: bomly-fuzz"]},"packages":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`,
		`{"artifacts":[],"artifactRelationships":[],"source":{"type":"directory","target":"."},"descriptor":{"name":"syft","version":"seed"},"schema":{"version":"16.0.34","url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.34.json"}}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		doc, target, err := UnmarshalAutoJSON(raw)
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
