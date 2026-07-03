package sbom

import "testing"

const maxFuzzInputSize = 1 << 20

func FuzzUnmarshalAutoJSON(f *testing.F) {
	for _, seed := range []string{
		`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"demo","documentNamespace":"https://example.com/spdx/demo","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: bomly-fuzz"]},"packages":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`,
		`{"artifacts":[],"artifactRelationships":[],"source":{"type":"directory","target":"."},"descriptor":{"name":"syft","version":"seed"}}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		doc, target, err := UnmarshalAutoJSON(raw)
		if err != nil || target == TargetSyftJSON {
			return
		}
		if doc == nil {
			t.Fatalf("successful %s parse returned nil document", target)
		}
		if _, err := MarshalJSON(doc, target, EncodeOptions{}); err != nil {
			return
		}
	})
}
