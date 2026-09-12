package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
)

// mergedExport ingests two documents, merges their graphs, and exports the
// result to one target -- the merge case ADR-0042 defines, where the document
// mints its own identity and links its sources.
func mergedExport(t *testing.T, target Target, raws ...string) ([]byte, []sdk.GraphEntry) {
	t.Helper()
	entries := make([]sdk.GraphEntry, 0, len(raws))
	merged := sdk.New()
	for _, raw := range raws {
		_, entry := ingestDocument(t, raw)
		entries = append(entries, entry)
		if err := sdk.MergeGraph(merged, entry.Graph); err != nil {
			t.Fatalf("merge: %v", err)
		}
	}
	raw, err := MarshalGraphEntriesJSON(merged, entries, target, BuildOptions{Created: fixedExportTime()}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return raw, entries
}

// spdxExternalDocumentRefs reads the externalDocumentRefs off a rendered SPDX
// document, as a consumer would.
func spdxExternalDocumentRefs(t *testing.T, raw []byte) []struct {
	ID       string `json:"externalDocumentId"`
	URI      string `json:"spdxDocument"`
	Checksum struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"checksumValue"`
	} `json:"checksum"`
} {
	t.Helper()
	var doc struct {
		Namespace string `json:"documentNamespace"`
		Refs      []struct {
			ID       string `json:"externalDocumentId"`
			URI      string `json:"spdxDocument"`
			Checksum struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"checksumValue"`
			} `json:"checksum"`
		} `json:"externalDocumentRefs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode spdx: %v", err)
	}
	return doc.Refs
}

// cycloneDXSourceRefs reads the document-level references of type "bom".
func cycloneDXSourceRefs(t *testing.T, raw []byte) []cdx.ExternalReference {
	t.Helper()
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("decode cyclonedx: %v", err)
	}
	if bom.ExternalReferences == nil {
		return nil
	}
	refs := make([]cdx.ExternalReference, 0, len(*bom.ExternalReferences))
	for _, ref := range *bom.ExternalReferences {
		if ref.Type == cdx.ERTypeBOM {
			refs = append(refs, ref)
		}
	}
	return refs
}

// A merged SPDX document names the documents it was built from.
//
// It could not before: SPDX links a document through externalDocumentRefs,
// every entry there requires a checksum over that document's bytes, and the
// document carrier had nowhere to hold one -- so the CycloneDX half of
// ADR-0042 shipped and the SPDX half was left open as
// bomly-dev/bomly-sdk#55. The checksum is captured at ingest, which is the
// only moment those bytes exist.
func TestMergedSPDXExportNamesItsSources(t *testing.T) {
	raw, _ := mergedExport(t, TargetSPDX23JSON, documentRichSPDX, serialCycloneDX)

	var doc struct {
		Namespace string `json:"documentNamespace"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Namespace == "https://acme.example/spdx/acme-platform-7f3c" {
		t.Error("the merged document adopted a source's identity instead of minting its own")
	}

	refs := spdxExternalDocumentRefs(t, raw)
	if len(refs) != 2 {
		t.Fatalf("externalDocumentRefs = %+v, want one per source\n%s", refs, raw)
	}
	byURI := make(map[string]string, len(refs))
	seenIDs := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if !strings.HasPrefix(ref.ID, "DocumentRef-") {
			t.Errorf("externalDocumentId = %q, want the mandatory DocumentRef- prefix", ref.ID)
		}
		if _, duplicate := seenIDs[ref.ID]; duplicate {
			t.Errorf("externalDocumentId %q is used twice", ref.ID)
		}
		seenIDs[ref.ID] = struct{}{}
		if ref.Checksum.Algorithm != "SHA256" {
			t.Errorf("checksum algorithm = %q, want SPDX's own spelling", ref.Checksum.Algorithm)
		}
		if len(ref.Checksum.Value) != 64 {
			t.Errorf("checksum for %q = %q, want a SHA-256 hex digest", ref.URI, ref.Checksum.Value)
		}
		byURI[ref.URI] = ref.Checksum.Value
	}
	if _, ok := byURI["https://acme.example/spdx/acme-platform-7f3c"]; !ok {
		t.Errorf("the SPDX source is not named: %+v", refs)
	}
	if _, ok := byURI["urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1"]; !ok {
		t.Errorf("the CycloneDX source is not named by its BOM-Link: %+v", refs)
	}

	// The two sources are different documents, so their checksums differ. A
	// single digest reused across every entry would be the shape of a bug
	// that hashes the export rather than each source.
	values := make(map[string]struct{}, len(byURI))
	for _, value := range byURI {
		values[value] = struct{}{}
	}
	if len(values) != len(byURI) {
		t.Errorf("the sources share a checksum: %+v", byURI)
	}
}

// The checksum a source link carries is a digest of that source document's
// own bytes, not of anything else. Asserted against the digest computed here
// so a change that hashes the wrong buffer cannot pass.
func TestSourceLinkChecksumCoversTheSourceBytes(t *testing.T) {
	raw, _ := mergedExport(t, TargetSPDX23JSON, documentRichSPDX, serialCycloneDX)

	want := map[string]string{
		"https://acme.example/spdx/acme-platform-7f3c":   sha256Hex(documentRichSPDX),
		"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1": sha256Hex(serialCycloneDX),
	}
	for _, ref := range spdxExternalDocumentRefs(t, raw) {
		expected, known := want[ref.URI]
		if !known {
			t.Errorf("unexpected source %q", ref.URI)
			continue
		}
		if ref.Checksum.Value != expected {
			t.Errorf("checksum for %q = %q, want a digest of that document's bytes %q", ref.URI, ref.Checksum.Value, expected)
		}
	}
}

// Converting a merged document again still names the documents behind it.
//
// The links used to be write-only: an export wrote them and ingest read
// nothing back, so the second conversion produced a document that claimed to
// be built from nothing (bomly-dev/bomly-sdk#61). Provenance now survives more
// than one hop, which is the SDK's declared merge class for the source set.
func TestMergedSourceLinksSurviveASecondConversion(t *testing.T) {
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX16JSON} {
		t.Run(string(target), func(t *testing.T) {
			first, _ := mergedExport(t, target, documentRichSPDX, serialCycloneDX)

			// The merged document, converted a second time. One source now,
			// so this is a conversion: it restates that document, and the
			// documents that document named are still named.
			_, entry := ingestDocument(t, string(first))
			second, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, target,
				BuildOptions{Created: fixedExportTime(), RestatesSource: true}, EncodeOptions{Pretty: true})
			if err != nil {
				t.Fatalf("second export: %v", err)
			}

			var named []string
			switch target {
			case TargetSPDX23JSON:
				for _, ref := range spdxExternalDocumentRefs(t, second) {
					named = append(named, ref.URI)
				}
			default:
				for _, ref := range cycloneDXSourceRefs(t, second) {
					named = append(named, ref.URL)
				}
			}
			for _, want := range []string{
				"https://acme.example/spdx/acme-platform-7f3c",
				"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1",
			} {
				if !containsStringValue(named, want) {
					t.Errorf("second export names %v, missing %q\n%s", named, want, second)
				}
			}
		})
	}
}

// A merged CycloneDX document carries each source's checksum on the link, so
// the tuple SPDX needs survives a CycloneDX hop. Without it, converting a
// merged CycloneDX document to SPDX could name no source at all -- the format
// requires the checksum and there would be nowhere left to recover it from.
func TestCycloneDXSourceLinksCarryTheirChecksum(t *testing.T) {
	raw, _ := mergedExport(t, TargetCycloneDX16JSON, documentRichSPDX, serialCycloneDX)
	refs := cycloneDXSourceRefs(t, raw)
	if len(refs) != 2 {
		t.Fatalf("bom references = %+v, want one per source\n%s", refs, raw)
	}
	for _, ref := range refs {
		if ref.Hashes == nil || len(*ref.Hashes) == 0 {
			t.Fatalf("the link to %q carries no hash\n%s", ref.URL, raw)
		}
	}

	// And converting that document to SPDX still names both sources, which is
	// the whole reason the hash is written.
	_, entry := ingestDocument(t, string(raw))
	converted, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, TargetSPDX23JSON,
		BuildOptions{Created: fixedExportTime(), RestatesSource: true}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("convert to spdx: %v", err)
	}
	if got := len(spdxExternalDocumentRefs(t, converted)); got != 2 {
		t.Errorf("externalDocumentRefs = %d, want both sources\n%s", got, converted)
	}
}

// A native scan names no sources: there were none.
func TestNativeExportNamesNoSources(t *testing.T) {
	g := scopedGraph(t, sdk.ScopeRuntime)
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX16JSON} {
		t.Run(string(target), func(t *testing.T) {
			raw, err := MarshalDepGraphJSON(g, target, BuildOptions{Created: fixedExportTime()}, EncodeOptions{Pretty: true})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			switch target {
			case TargetSPDX23JSON:
				if refs := spdxExternalDocumentRefs(t, raw); len(refs) != 0 {
					t.Errorf("externalDocumentRefs = %+v, want none", refs)
				}
			default:
				if refs := cycloneDXSourceRefs(t, raw); len(refs) != 0 {
					t.Errorf("bom references = %+v, want none", refs)
				}
			}
		})
	}
}

// A conversion does not link the document it restates: it *is* that document.
// Only the documents behind it are named.
func TestConversionDoesNotLinkTheDocumentItRestates(t *testing.T) {
	_, entry := ingestDocument(t, documentRichSPDX)
	raw, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, TargetSPDX23JSON,
		BuildOptions{Created: fixedExportTime(), RestatesSource: true}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if refs := spdxExternalDocumentRefs(t, raw); len(refs) != 0 {
		t.Errorf("externalDocumentRefs = %+v, want none: the export adopted that identity", refs)
	}
}

func containsStringValue(values []string, want string) bool {
	return slices.Contains(values, want)
}

// sha256Hex is the digest form the ingest checksum is written in.
func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Two sources whose identities reduce to the same SPDX idstring still get
// distinct reference ids.
//
// The idstring alphabet is narrow -- letters, digits, "." and "-" -- so two
// different URIs can sanitize to one id, and SPDX requires each
// externalDocumentId to be unique within a document. Nothing in tools-golang
// or the SDK mints one, so this package reuses its own package-id rule
// including the collision suffix; this is the case that says so.
func TestCollidingSourceIdentitiesGetDistinctReferenceIDs(t *testing.T) {
	checksum := sdk.Digest{
		Algorithm: sdk.DigestAlgorithmSHA256,
		Value:     "0000000000000000000000000000000000000000000000000000000000000000",
	}
	doc := &Document{
		Namespace: "https://bomly.dev/spdx/merged",
		Sources: []sdk.DocumentAssertions{
			{Identity: "https://acme.example/a_b", Checksum: &checksum},
			{Identity: "https://acme.example/a+b", Checksum: &checksum},
		},
	}
	refs := spdxSourceLinks(doc)
	if len(refs) != 2 {
		t.Fatalf("refs = %+v, want one per source", refs)
	}
	if refs[0].DocumentRefID == refs[1].DocumentRefID {
		t.Errorf("both sources share the id %q; SPDX requires them to be distinct", refs[0].DocumentRefID)
	}
}
