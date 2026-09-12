package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
)

// documentRichSPDX asserts document-level claims: an identity, a name, named
// creators of both kinds, a tool, and a comment.
const documentRichSPDX = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "acme-platform-bom",
  "documentNamespace": "https://acme.example/spdx/acme-platform-7f3c",
  "comment": "Produced for the quarterly release review.",
  "creationInfo": {
    "created": "2026-01-02T03:04:05Z",
    "creators": ["Organization: Acme Corp", "Person: Dana Scully (dana@acme.example)", "Tool: acme-sbom-2.4.1"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-widget",
      "name": "widget",
      "versionInfo": "1.0.0",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/widget@1.0.0"}
      ]
    }
  ]
}`

// serialCycloneDX is a CycloneDX document that identifies itself: it carries
// a serial number, which is what a BOM-Link is built from.
const serialCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-01-03T04:05:06Z",
    "tools": { "components": [ { "type": "application", "name": "cdx-gen", "version": "9.1.0" } ] }
  },
  "components": [
    {
      "bom-ref": "pkg:npm/gadget@2.0.0",
      "type": "library",
      "name": "gadget",
      "version": "2.0.0",
      "purl": "pkg:npm/gadget@2.0.0"
    }
  ]
}`

// fixedExportTime pins the timestamp an export stamps, so two runs differ
// only in what they preserved.
func fixedExportTime() time.Time {
	return time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)
}

// ingestDocument reads a document and returns the graph entry it becomes,
// the way the sbom detector builds one.
func ingestDocument(t *testing.T, raw string) (*sdk.Graph, sdk.GraphEntry) {
	t.Helper()
	doc, _, err := UnmarshalAutoJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	g, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	return g, sdk.GraphEntry{Graph: g, Document: DocumentAssertionsFor(doc)}
}

// An ingested document's own claims survive the graph hop, which is where
// they used to be dropped: a merged graph has no record of which document it
// came from.
func TestDocumentClaimsSurviveTheGraphHop(t *testing.T) {
	_, entry := ingestDocument(t, documentRichSPDX)
	if entry.Document == nil {
		t.Fatal("the entry carries no document assertions")
	}
	got := *entry.Document
	if got.Identity != "https://acme.example/spdx/acme-platform-7f3c" {
		t.Errorf("identity = %q", got.Identity)
	}
	if got.Name != "acme-platform-bom" {
		t.Errorf("name = %q", got.Name)
	}
	if got.DataLicense != "CC0-1.0" {
		t.Errorf("data license = %q", got.DataLicense)
	}
	if got.Created != "2026-01-02T03:04:05Z" {
		t.Errorf("created = %q", got.Created)
	}
	if !strings.Contains(got.Comment, "quarterly release") {
		t.Errorf("comment = %q", got.Comment)
	}
	var org, person bool
	for _, creator := range got.Creators {
		switch creator.Kind {
		case sdk.ContactKindOrganization:
			org = org || creator.Name == "Acme Corp"
		case sdk.ContactKindPerson:
			person = person || creator.Name == "Dana Scully"
		}
	}
	if !org || !person {
		t.Errorf("creators = %+v, want both Acme Corp and Dana Scully", got.Creators)
	}
	if len(got.Tools) != 1 || got.Tools[0].Name != "acme-sbom-2.4.1" {
		t.Errorf("tools = %+v", got.Tools)
	}
	// The address the source stated is not retained -- the SDK's contact gate
	// strips it, and this asserts the gate is actually on this path.
	for _, creator := range got.Creators {
		if strings.Contains(creator.Name, "@") {
			t.Errorf("an email address survived into a creator: %q", creator.Name)
		}
	}
}

// The fixed point issue #396 asks for: a single-source export, re-ingested
// and re-exported, is byte-identical.
//
// Nothing is pinned. Neither the identity nor the timestamp is supplied by the
// caller, because a conversion takes both from its source -- so a value that
// drifted, or was silently replaced by this run's clock, shows up here as a
// byte difference. Pinning them would have made this test pass over exactly
// the defects it exists to catch.
func TestSingleSourceExportIsAFixedPoint(t *testing.T) {
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX16JSON} {
		t.Run(string(target), func(t *testing.T) {
			opts := BuildOptions{ToolVersion: "0.0.0-test"}

			_, entry := ingestDocument(t, supplierRichCycloneDX)
			first, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, target, opts, EncodeOptions{Pretty: true})
			if err != nil {
				t.Fatalf("first export: %v", err)
			}

			_, reingested := ingestDocument(t, string(first))
			second, err := MarshalGraphEntriesJSON(reingested.Graph, []sdk.GraphEntry{reingested}, target, opts, EncodeOptions{Pretty: true})
			if err != nil {
				t.Fatalf("second export: %v", err)
			}

			if !bytes.Equal(first, second) {
				t.Errorf("export -> ingest -> export is not a fixed point.\nfirst:\n%s\nsecond:\n%s", first, second)
			}
		})
	}
}

// A conversion adopts its single source's identity, so the document it
// produces still says which document it restates.
func TestSingleSourceExportAdoptsTheSourceIdentity(t *testing.T) {
	_, entry := ingestDocument(t, documentRichSPDX)
	doc, err := FromGraphEntries(entry.Graph, []sdk.GraphEntry{entry}, BuildOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if doc.Namespace != "https://acme.example/spdx/acme-platform-7f3c" {
		t.Errorf("namespace = %q, want the source's", doc.Namespace)
	}
	if doc.Name != "acme-platform-bom" {
		t.Errorf("name = %q, want the source's", doc.Name)
	}
	if len(doc.Sources) != 1 {
		t.Fatalf("sources = %+v, want the one ingested document", doc.Sources)
	}
	// Not linked in the format that adopted it: the link would point at this
	// document itself.
	if links := documentSourceLinks(doc, documentIdentity{Namespace: doc.Namespace}); len(links) != 0 {
		t.Errorf("a source whose identity was adopted was also linked: %+v", links)
	}
}

// A caller-pinned identity wins over the source's, so `--sbom-namespace`
// still means what it says.
func TestPinnedIdentityWinsOverTheSource(t *testing.T) {
	_, entry := ingestDocument(t, documentRichSPDX)
	doc, err := FromGraphEntries(entry.Graph, []sdk.GraphEntry{entry}, BuildOptions{
		DocumentNS:   "https://pinned.example/ns",
		DocumentName: "pinned-name",
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if doc.Namespace != "https://pinned.example/ns" {
		t.Errorf("namespace = %q, want the pinned one", doc.Namespace)
	}
	if doc.Name != "pinned-name" {
		t.Errorf("name = %q, want the pinned one", doc.Name)
	}
}

// A merged export states its own identity and links each source, rather than
// adopting one of them: both formats give a document exactly one identity,
// and picking a source's would name a document that is not this one.
func TestMergedExportLinksItsSourcesInsteadOfAdoptingOne(t *testing.T) {
	_, spdxEntry := ingestDocument(t, documentRichSPDX)
	_, cdxEntry := ingestDocument(t, serialCycloneDX)
	entries := []sdk.GraphEntry{spdxEntry, cdxEntry}

	merged := sdk.New()
	for _, entry := range entries {
		if err := sdk.MergeGraph(merged, entry.Graph); err != nil {
			t.Fatalf("merge: %v", err)
		}
	}

	doc, err := FromGraphEntries(merged, entries, BuildOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if doc.Namespace == "https://acme.example/spdx/acme-platform-7f3c" {
		t.Error("the merged document adopted a source's identity")
	}
	if !strings.HasPrefix(doc.Namespace, "https://bomly.dev/spdx/") {
		t.Errorf("namespace = %q, want a freshly minted one", doc.Namespace)
	}
	if len(doc.Sources) != 2 {
		t.Fatalf("sources = %d, want both documents", len(doc.Sources))
	}

	// Both sources' creators and tools are credited: that is the SDK's
	// declared merge class for these fields, and a merged document that
	// dropped one source's credit would be asserting authorship it does not
	// have.
	var acme, widgetTool bool
	for _, creator := range doc.Assertions.Creators {
		acme = acme || creator.Name == "Acme Corp"
	}
	for _, tool := range doc.Assertions.Tools {
		widgetTool = widgetTool || tool.Name == "acme-sbom-2.4.1"
	}
	if !acme || !widgetTool {
		t.Errorf("merged credit lost: creators=%+v tools=%+v", doc.Assertions.Creators, doc.Assertions.Tools)
	}

	links := documentSourceLinks(doc, documentIdentity{Serial: doc.SerialNumber})
	if len(links) != 2 {
		t.Fatalf("links = %+v, want one per source", links)
	}
	// Each link is a full tuple, not a bare identity: the checksum is what
	// SPDX's externalDocumentRef requires on every entry, and it can only be
	// computed while the source's original bytes are in hand.
	for _, link := range links {
		if link.Identity == "" {
			t.Errorf("link %+v names no document", link)
		}
		if link.Checksum == nil {
			t.Errorf("link %q carries no checksum, so SPDX cannot name it", link.Identity)
		}
	}
}

// The CycloneDX projection of those links: root-level external references of
// type "bom", carrying a BOM-Link for a CycloneDX source and the namespace
// URI for an SPDX one, exactly as ADR-0037 states.
func TestMergedCycloneDXExportCarriesSourceBOMLinks(t *testing.T) {
	_, spdxEntry := ingestDocument(t, documentRichSPDX)
	_, cdxEntry := ingestDocument(t, serialCycloneDX)
	entries := []sdk.GraphEntry{spdxEntry, cdxEntry}

	merged := sdk.New()
	for _, entry := range entries {
		if err := sdk.MergeGraph(merged, entry.Graph); err != nil {
			t.Fatalf("merge: %v", err)
		}
	}
	raw, err := MarshalGraphEntriesJSON(merged, entries, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if bom.ExternalReferences == nil {
		t.Fatalf("the merged document links no sources:\n%s", raw)
	}
	var namespaceLink, bomLink bool
	for _, ref := range *bom.ExternalReferences {
		if ref.Type != cdx.ERTypeBOM {
			continue
		}
		namespaceLink = namespaceLink || ref.URL == "https://acme.example/spdx/acme-platform-7f3c"
		bomLink = bomLink || cdx.IsBOMLink(ref.URL)
	}
	if !namespaceLink {
		t.Errorf("the SPDX source's namespace is not linked: %+v", *bom.ExternalReferences)
	}
	if !bomLink {
		t.Errorf("the CycloneDX source is not linked as a BOM-Link: %+v", *bom.ExternalReferences)
	}
}

// A source document's claims are re-gated on the way out, not trusted because
// they were gated on the way in. The entry is reachable by any detector or
// external plugin, so a value written straight onto it must still be refused.
func TestSourceClaimsAreRegatedOnExport(t *testing.T) {
	_, entry := ingestDocument(t, supplierRichCycloneDX)
	entry.Document = &sdk.DocumentAssertions{
		Identity: "not a valid iri at all",
		Name:     "line\nbreak",
		Comment:  strings.Repeat("x", 1<<20),
		Creators: []sdk.Contact{{Kind: sdk.ContactKindPerson, Name: "ctrl\x00char"}},
	}
	doc, err := FromGraphEntries(entry.Graph, []sdk.GraphEntry{entry}, BuildOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if strings.Contains(doc.Namespace, "not a valid iri") {
		t.Errorf("an unpublishable identity reached the document: %q", doc.Namespace)
	}
	if strings.Contains(doc.Name, "\n") {
		t.Errorf("a line break reached the document name: %q", doc.Name)
	}
	if strings.Contains(doc.Assertions.Comment, "xxxx") {
		t.Error("an over-long comment reached the document")
	}
	for _, creator := range doc.Assertions.Creators {
		if strings.ContainsRune(creator.Name, 0) {
			t.Errorf("a control character reached a creator: %q", creator.Name)
		}
	}
}

// Bomly's own credit is not duplicated when a source already credited the
// same tool at the same version, which is what would otherwise make each hop
// of a round trip grow the creator list.
func TestBomlyCreditIsNotDuplicatedAcrossHops(t *testing.T) {
	opts := BuildOptions{ToolVersion: "0.0.0-test", Created: fixedExportTime()}
	_, entry := ingestDocument(t, supplierRichCycloneDX)
	first, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, TargetSPDX23JSON, opts, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("first export: %v", err)
	}
	_, second := ingestDocument(t, string(first))
	doc, err := FromGraphEntries(second.Graph, []sdk.GraphEntry{second}, opts)
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	creators := spdxDocumentCreators(doc)
	seen := map[string]int{}
	for _, creator := range creators {
		seen[creator.CreatorType+": "+creator.Creator]++
	}
	for line, count := range seen {
		if count > 1 {
			t.Errorf("creator %q appears %d times: %+v", line, count, creators)
		}
	}
}

// Converting SPDX to CycloneDX names the source. The namespace is adopted into
// the model, but CycloneDX has no namespace slot and writes a freshly minted
// serial instead -- so the source has to be linked, or the exported document
// says nothing at all about where it came from.
func TestCycloneDXConversionLinksAnSPDXSourceItCannotAdopt(t *testing.T) {
	_, entry := ingestDocument(t, documentRichSPDX)
	raw, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bom.ExternalReferences == nil {
		t.Fatalf("the conversion names its source neither by identity nor by link:\n%s", raw)
	}
	var linked bool
	for _, ref := range *bom.ExternalReferences {
		linked = linked || (ref.Type == cdx.ERTypeBOM && ref.URL == "https://acme.example/spdx/acme-platform-7f3c")
	}
	if !linked {
		t.Errorf("the SPDX source is not linked: %+v", *bom.ExternalReferences)
	}
}

// A CycloneDX source Bomly *can* adopt is not also linked -- the link would
// point at this document itself.
func TestCycloneDXConversionDoesNotLinkTheIdentityItAdopted(t *testing.T) {
	_, entry := ingestDocument(t, serialCycloneDX)
	raw, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bom.SerialNumber != "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" {
		t.Fatalf("serial = %q, want the source's", bom.SerialNumber)
	}
	if bom.ExternalReferences != nil {
		for _, ref := range *bom.ExternalReferences {
			if ref.Type == cdx.ERTypeBOM {
				t.Errorf("the document links itself: %+v", ref)
			}
		}
	}
}

// A document that asserted nothing about itself still counts as a source, so
// merging it with an identified document is a merge and not a conversion.
//
// CycloneDX permits a document with neither a serial number nor metadata, and
// treating it as absent made the export adopt the other source's identity --
// publishing a merged inventory under the name of one of its inputs.
func TestAnAnonymousSourceStillCountsAsASource(t *testing.T) {
	const anonymous = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {"bom-ref": "pkg:npm/quiet@1.0.0", "type": "library", "name": "quiet",
     "version": "1.0.0", "purl": "pkg:npm/quiet@1.0.0"}
  ]
}`
	_, anonEntry := ingestDocument(t, anonymous)
	if anonEntry.Document == nil {
		t.Fatal("an ingested document with no claims left no record that it was read")
	}
	_, spdxEntry := ingestDocument(t, documentRichSPDX)
	entries := []sdk.GraphEntry{anonEntry, spdxEntry}

	merged := sdk.New()
	for _, entry := range entries {
		if err := sdk.MergeGraph(merged, entry.Graph); err != nil {
			t.Fatalf("merge: %v", err)
		}
	}
	doc, err := FromGraphEntries(merged, entries, BuildOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if doc.Namespace == "https://acme.example/spdx/acme-platform-7f3c" {
		t.Error("a merge of two documents adopted one source's identity")
	}
	if len(doc.Sources) != 2 {
		t.Errorf("sources = %d, want both documents counted", len(doc.Sources))
	}
}

// A conversion states the source's creation time, not this run's clock. The
// document claims the source's identity; claiming its identity and a different
// creation time is two statements that disagree.
func TestConversionKeepsTheSourceCreationTime(t *testing.T) {
	_, entry := ingestDocument(t, documentRichSPDX)
	doc, err := FromGraphEntries(entry.Graph, []sdk.GraphEntry{entry}, BuildOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if got := doc.Created.UTC().Format(time.RFC3339); got != "2026-01-02T03:04:05Z" {
		t.Errorf("created = %q, want the source's", got)
	}
}

// An organization a source credited survives a CycloneDX round trip. The
// format has one slot for it, and the export used to fill that slot only from
// configured provenance.
func TestCycloneDXCreditsAnIngestedOrganization(t *testing.T) {
	_, entry := ingestDocument(t, documentRichSPDX)
	raw, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bom.Metadata == nil || bom.Metadata.Manufacturer == nil || bom.Metadata.Manufacturer.Name != "Acme Corp" {
		t.Errorf("manufacturer = %+v, want the source's organization", bom.Metadata.Manufacturer)
	}
}

// Configured provenance still wins over an ingested organization: that is the
// operator saying who produced this run.
func TestConfiguredProvenanceOutranksAnIngestedOrganization(t *testing.T) {
	_, entry := ingestDocument(t, documentRichSPDX)
	doc, err := FromGraphEntries(entry.Graph, []sdk.GraphEntry{entry}, BuildOptions{
		Provenance: Provenance{Manufacturer: "Operator Ltd"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if got := cycloneDXDocumentManufacturer(doc); got == nil || got.Name != "Operator Ltd" {
		t.Errorf("manufacturer = %+v, want the configured one", got)
	}
}

// The record exists for a document that asserted nothing, which is what makes
// a merge involving such a document read as a merge.
//
// "Asserted nothing" is about the claims the document made: no identity, no
// name, no creators, no tools. The record is no longer empty even then,
// because ingest stamps a checksum over the bytes it read -- the value SPDX's
// externalDocumentRef requires and that nothing downstream can recompute.
func TestDocumentAssertionsForAlwaysRecordsThatADocumentWasRead(t *testing.T) {
	doc, _, err := UnmarshalAutoJSON([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}`))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	got := DocumentAssertionsFor(doc)
	if got == nil {
		t.Fatal("a document that asserted nothing left no record that it was read")
	}
	if got.Identity != "" || got.Name != "" || got.DataLicense != "" || got.Comment != "" ||
		len(got.Creators) != 0 || len(got.Tools) != 0 || len(got.Sources) != 0 {
		t.Errorf("assertions = %+v, want no claims of its own", *got)
	}
	if got.Checksum == nil {
		t.Errorf("assertions = %+v, want the ingest-captured checksum", *got)
	}
	if DocumentAssertionsFor(nil) != nil {
		t.Error("no document must mean no record")
	}
}

// A credited tool keeps everything the format can hold. A CycloneDX source
// naming "Acme / cdx-gen / 9.1.0" was reduced to "Tool: cdx-gen" on SPDX
// export, and suppressed entirely on CycloneDX export by a deduplication key
// that ignored the vendor.
func TestCreditedToolsKeepWhatEachFormatCanHold(t *testing.T) {
	doc := &Document{
		Tool:        defaultToolName,
		Tools:       []string{defaultToolName},
		ToolVersion: "1.2.3",
		Assertions: sdk.DocumentAssertions{Tools: []sdk.DocumentTool{
			{Vendor: "Acme", Name: "cdx-gen", Version: "9.1.0"},
			// Same name and version as Bomly's own entry, but with a vendor
			// the source added: the SDK's merge class keys on the whole
			// triple, so this is a distinct tool and must not be swallowed.
			{Vendor: "Acme", Name: defaultToolName, Version: "1.2.3"},
		}},
	}

	t.Run("spdx renders name and version", func(t *testing.T) {
		var found bool
		for _, creator := range spdxDocumentCreators(doc) {
			found = found || creator.Creator == "cdx-gen-9.1.0"
		}
		if !found {
			t.Errorf("creators = %+v, want the tool's version kept", spdxDocumentCreators(doc))
		}
	})

	t.Run("cyclonedx keeps the vendor", func(t *testing.T) {
		tools := cycloneDXMetadataTools(doc)
		if tools == nil || tools.Components == nil {
			t.Fatal("no tools rendered")
		}
		var vendored, ownVendored bool
		for _, component := range *tools.Components {
			if component.Manufacturer == nil {
				continue
			}
			vendored = vendored || (component.Name == "cdx-gen" && component.Manufacturer.Name == "Acme")
			ownVendored = ownVendored || (component.Name == defaultToolName && component.Manufacturer.Name == "Acme")
		}
		if !vendored {
			t.Errorf("tools = %+v, want the source's vendor kept", *tools.Components)
		}
		if !ownVendored {
			t.Errorf("a source tool differing only by vendor was suppressed: %+v", *tools.Components)
		}
	})
}

// A serial names a BOM; the revision names which issue of it. Adopting one
// without the other produced a document claiming to be revision 1 of a BOM
// whose revision 2 it had actually converted -- and, because the self-link
// check compared serials alone, it linked nothing either.
func TestConversionKeepsTheSourceBOMRevision(t *testing.T) {
	source := strings.Replace(serialCycloneDX, `"version": 1,`, `"version": 4,`, 1)
	_, entry := ingestDocument(t, source)
	if entry.Document.Identity != "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/4" {
		t.Fatalf("identity = %q, want the revision kept", entry.Document.Identity)
	}
	raw, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bom.Version != 4 {
		t.Errorf("version = %d, want the source's revision", bom.Version)
	}
	if bom.SerialNumber != "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" {
		t.Errorf("serial = %q", bom.SerialNumber)
	}
	// Adopted, so not also linked.
	if bom.ExternalReferences != nil {
		for _, ref := range *bom.ExternalReferences {
			if ref.Type == cdx.ERTypeBOM {
				t.Errorf("the document links itself: %+v", ref)
			}
		}
	}
}

// A different revision of the same serial is a different document, so it is
// linked rather than treated as this document itself.
func TestADifferentRevisionOfTheSameSerialIsStillASource(t *testing.T) {
	doc := &Document{
		SerialNumber:  "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		SerialVersion: 1,
		Sources: []sdk.DocumentAssertions{
			{Identity: "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/7"},
		},
	}
	links := documentSourceLinks(doc, documentIdentity{Serial: doc.SerialNumber, SerialVersion: doc.SerialVersionOrDefault()})
	if len(links) != 1 {
		t.Fatalf("links = %+v, want revision 7 named as a source of revision 1", links)
	}
}

// Bomly's own output re-ingests without growing its author list. Configured
// provenance is written as an author as well as the manufacturer, so the name
// comes back as a person creator and used to be appended a second time -- one
// extra author per hop, in a flow advertised as a fixed point.
func TestConfiguredProvenanceDoesNotDuplicateAuthorsAcrossHops(t *testing.T) {
	opts := BuildOptions{
		Provenance:   Provenance{Manufacturer: "Operator Ltd"},
		Created:      fixedExportTime(),
		SerialNumber: "urn:uuid:11111111-2222-4333-8444-555555555555",
	}
	_, entry := ingestDocument(t, supplierRichCycloneDX)
	first, err := MarshalGraphEntriesJSON(entry.Graph, []sdk.GraphEntry{entry}, TargetCycloneDX16JSON, opts, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("first export: %v", err)
	}
	_, again := ingestDocument(t, string(first))
	second, err := MarshalGraphEntriesJSON(again.Graph, []sdk.GraphEntry{again}, TargetCycloneDX16JSON, opts, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("a provenance-configured export is not a fixed point.\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}
