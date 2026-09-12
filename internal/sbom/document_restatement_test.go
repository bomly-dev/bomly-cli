package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
)

// A single source whose graph was transformed after ingest -- scope-filtered,
// enriched, degraded -- is a different document with one input, and it says
// so: its own identity, timestamp, name and comment, with the source linked
// rather than adopted (ADR-0042 as amended by issue #433). Before the
// amendment a `--scope runtime` export of one SBOM republished that SBOM's
// namespace over a subset of its inventory, two documents sharing one name.
//
// The caller's declaration is the only signal; this package cannot tell a
// filtered graph from a whole one. So the default -- no declaration -- is the
// safe side, and these tests pass no RestatesSource at all.
func TestATransformedConversionMintsItsOwnIdentity(t *testing.T) {
	_, entry := ingestDocument(t, documentRichSPDX)
	doc, err := FromGraphEntries(entry.Graph, []sdk.GraphEntry{entry}, BuildOptions{Created: fixedExportTime()})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	const sourceNamespace = "https://acme.example/spdx/acme-platform-7f3c"
	if doc.Namespace == sourceNamespace {
		t.Fatalf("a transformed export republished its source's namespace %q", doc.Namespace)
	}
	if !strings.HasPrefix(doc.Namespace, "https://bomly.dev/spdx/") {
		t.Fatalf("namespace = %q, want one minted by this export", doc.Namespace)
	}
	if doc.Name != defaultDocumentName {
		t.Fatalf("name = %q, want the default rather than the source's", doc.Name)
	}
	if doc.Assertions.Comment != "" {
		t.Fatalf("comment = %q, want none: it described the source's full contents", doc.Assertions.Comment)
	}
	if !doc.Created.Equal(fixedExportTime()) {
		t.Fatalf("created = %v, want this export's own time %v, not the source's", doc.Created, fixedExportTime())
	}
	if len(doc.Sources) != 1 {
		t.Fatalf("sources = %d, want the one document read", len(doc.Sources))
	}
	// Creators still union: the source did produce this document's inventory.
	var credited bool
	for _, creator := range doc.Assertions.Creators {
		if creator.Name == "Acme Corp" {
			credited = true
		}
	}
	if !credited {
		t.Fatalf("creators = %+v, want the source's organization credited", doc.Assertions.Creators)
	}
}

// The identity a transformed export does not adopt is not lost: it is written
// as a link, in whichever form the target format has for one.
func TestATransformedConversionLinksItsSource(t *testing.T) {
	t.Run("spdx", func(t *testing.T) {
		_, entry := ingestDocument(t, documentRichSPDX)
		raw, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, TargetSPDX23JSON,
			BuildOptions{Created: fixedExportTime()}, EncodeOptions{Pretty: true})
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		refs := spdxExternalDocumentRefs(t, raw)
		if len(refs) != 1 {
			t.Fatalf("externalDocumentRefs = %+v, want exactly the source", refs)
		}
		if refs[0].URI != "https://acme.example/spdx/acme-platform-7f3c" {
			t.Fatalf("linked %q, want the source namespace", refs[0].URI)
		}
		if refs[0].Checksum.Value != sha256Hex(documentRichSPDX) {
			t.Fatalf("checksum = %q, want a digest of the source bytes", refs[0].Checksum.Value)
		}
	})
	t.Run("cyclonedx", func(t *testing.T) {
		_, entry := ingestDocument(t, serialCycloneDX)
		raw, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, TargetCycloneDX16JSON,
			BuildOptions{Created: fixedExportTime()}, EncodeOptions{Pretty: true})
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		var bom cdx.BOM
		if err := json.Unmarshal(raw, &bom); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if bom.SerialNumber == "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" {
			t.Fatalf("a transformed export republished its source's serial %q", bom.SerialNumber)
		}
		refs := cycloneDXSourceRefs(t, raw)
		if len(refs) != 1 {
			t.Fatalf("bom references = %+v, want exactly the source", refs)
		}
		if refs[0].URL != "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1" {
			t.Fatalf("linked %q, want the source's BOM-Link", refs[0].URL)
		}
		if refs[0].Hashes == nil || len(*refs[0].Hashes) == 0 {
			t.Fatalf("the source link carries no hash")
		}
	})
}

// The declaration means nothing for a merge: two sources are two documents
// whatever the caller says, and both are linked.
func TestRestatementFlagIsIgnoredByAMerge(t *testing.T) {
	_, first := ingestDocument(t, documentRichSPDX)
	_, second := ingestDocument(t, serialCycloneDX)
	merged := sdk.New()
	if err := sdk.MergeGraph(merged, first.Graph); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if err := sdk.MergeGraph(merged, second.Graph); err != nil {
		t.Fatalf("merge: %v", err)
	}
	doc, err := FromGraphEntries(merged, []sdk.GraphEntry{first, second}, BuildOptions{RestatesSource: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if doc.Namespace == "https://acme.example/spdx/acme-platform-7f3c" {
		t.Fatalf("a merge adopted one source's namespace despite the flag")
	}
	if got := documentSourceLinks(doc, documentIdentity{Namespace: doc.Namespace}); len(got) != 2 {
		t.Fatalf("source links = %+v, want both documents", got)
	}
}
