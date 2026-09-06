package sbom

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

// supplierRichCycloneDX is a document asserting the fields #396 exists to
// preserve: supplier, publisher, description, a checksum, a CPE, and a
// classified external reference.
const supplierRichCycloneDX = `{
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
      "description": "A widget for widgeting.",
      "publisher": "Widget Publishing Inc",
      "supplier": { "name": "Widget Supply Co", "url": ["https://widgets.example/"] },
      "cpe": "cpe:2.3:a:widget:widget:1.0.0:*:*:*:*:*:*:*",
      "hashes": [
        { "alg": "SHA-256", "content": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }
      ],
      "externalReferences": [
        { "type": "issue-tracker", "url": "https://widgets.example/issues", "comment": "public tracker" }
      ]
    }
  ]
}`

// assertPreserved states what every hop has to keep, so one helper covers
// CycloneDX, SPDX, and the graph.
func assertPreserved(t *testing.T, where string, component Component) {
	t.Helper()
	if component.Supplier == nil || component.Supplier.Name != "Widget Supply Co" {
		t.Fatalf("%s: supplier = %+v, want the source's", where, component.Supplier)
	}
	if component.Originator == nil || !strings.Contains(component.Originator.Name, "Widget Publishing") {
		t.Fatalf("%s: originator = %+v, want the source's publisher", where, component.Originator)
	}
	if !strings.Contains(component.Description, "widgeting") {
		t.Fatalf("%s: description = %q, want the source's", where, component.Description)
	}
	// Values, not presence. A conversion that kept a checksum entry while
	// changing its algorithm or digest, or kept a reference while relabelling
	// its type, would satisfy a presence check and still have corrupted the
	// claim -- and the algorithm names differ between the two formats, which
	// is exactly where such a slip would hide.
	var digest Digest
	for _, candidate := range component.Digests {
		if strings.EqualFold(strings.ReplaceAll(candidate.Algorithm, "-", ""), "sha256") {
			digest = candidate
		}
	}
	if digest.Value != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("%s: sha-256 checksum = %+v, want the source's", where, component.Digests)
	}
	if len(component.CPEs) == 0 || component.CPEs[0] != "cpe:2.3:a:widget:widget:1.0.0:*:*:*:*:*:*:*" {
		t.Fatalf("%s: CPE = %v, want the source's", where, component.CPEs)
	}
	var tracker bool
	for _, ref := range component.ExternalReferences {
		if ref.Locator != "https://widgets.example/issues" {
			continue
		}
		tracker = true
		if !strings.EqualFold(ref.Type, "issue-tracker") {
			t.Fatalf("%s: the issue-tracker reference was relabelled %q", where, ref.Type)
		}
	}
	if !tracker {
		t.Fatalf("%s: the issue-tracker reference was lost: %+v", where, component.ExternalReferences)
	}
}

// componentNamed finds a component by name, failing the test when absent.
func componentNamed(t *testing.T, doc *Document, name string) Component {
	t.Helper()
	for _, component := range doc.Components {
		if component.Name == name {
			return component
		}
	}
	t.Fatalf("component %q missing from document: %+v", name, doc.Components)
	return Component{}
}

// A supplier-rich CycloneDX document converts to SPDX and back without losing
// what it asserted. This is #396's first acceptance criterion, and it fails
// at the graph hop rather than in a codec: before this change the only things
// crossing Document -> Graph -> Document were coordinates, scope, copyright
// and licenses.
func TestSupplierRichDocumentSurvivesConversionToSPDXAndBack(t *testing.T) {
	ingested, err := UnmarshalJSON([]byte(supplierRichCycloneDX), TargetCycloneDX15JSON)
	if err != nil {
		t.Fatalf("ingest cyclonedx: %v", err)
	}
	assertPreserved(t, "cyclonedx ingest", componentNamed(t, ingested, "widget"))

	// Through the graph, which is where the loss used to happen.
	graph, err := ToGraph(ingested)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	asSPDX, err := MarshalDepGraphJSON(graph, TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	backFromSPDX, err := UnmarshalJSON(asSPDX, TargetSPDX23JSON)
	if err != nil {
		t.Fatalf("ingest spdx: %v", err)
	}
	assertPreserved(t, "spdx round trip", componentNamed(t, backFromSPDX, "widget"))

	// And back to CycloneDX, so neither format is a one-way door.
	spdxGraph, err := ToGraph(backFromSPDX)
	if err != nil {
		t.Fatalf("spdx to graph: %v", err)
	}
	asCDX, err := MarshalDepGraphJSON(spdxGraph, TargetCycloneDX15JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	backFromCDX, err := UnmarshalJSON(asCDX, TargetCycloneDX15JSON)
	if err != nil {
		t.Fatalf("re-ingest cyclonedx: %v", err)
	}
	assertPreserved(t, "cyclonedx round trip", componentNamed(t, backFromCDX, "widget"))
}

// Ingest must not set Source: it feeds RegistryMatchEligible, and an ingested
// component has to stay eligible or `bomly scan --sbom --enrich` stops
// enriching anything.
func TestIngestLeavesComponentsEligibleForEnrichment(t *testing.T) {
	ingested, err := UnmarshalJSON([]byte(supplierRichCycloneDX), TargetCycloneDX15JSON)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	graph, err := ToGraph(ingested)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	nodes := graph.DependencyNodes()
	if len(nodes) == 0 {
		t.Fatalf("no dependency nodes")
	}
	for _, node := range nodes {
		if node.Source != "" {
			t.Fatalf("ingest set Source = %q; that feeds RegistryMatchEligible and would stop --sbom --enrich", node.Source)
		}
		if !node.RegistryMatchEligible() {
			t.Fatalf("ingested %q is not eligible for enrichment", node.NodeID())
		}
	}
	_ = sdk.EcosystemUnknown
}

// A homepage survives a CycloneDX hop. The format has no homepage field, so it
// travels as the website reference CycloneDX offers for the same claim -- and
// used to travel nowhere at all, disappearing on any SPDX-to-CycloneDX
// conversion.
func TestHomepageSurvivesCycloneDX(t *testing.T) {
	const spdxWithHomepage = `{
  "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
  "name": "h", "documentNamespace": "https://h.example/spdx/1",
  "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: t"]},
  "packages": [{
    "SPDXID": "SPDXRef-w", "name": "widget", "versionInfo": "1.0.0",
    "homepage": "https://widget.example/",
    "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
      "referenceLocator": "pkg:npm/widget@1.0.0"}]
  }]
}`
	doc, _, err := UnmarshalAutoJSON([]byte(spdxWithHomepage))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := componentNamed(t, doc, "widget").Homepage; got != "https://widget.example/" {
		t.Fatalf("ingested homepage = %q", got)
	}
	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	cyclone, err := MarshalDepGraphJSON(graph, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("cyclonedx export: %v", err)
	}
	back, _, err := UnmarshalAutoJSON(cyclone)
	if err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	if got := componentNamed(t, back, "widget").Homepage; got != "https://widget.example/" {
		t.Fatalf("homepage after the CycloneDX hop = %q\n%s", got, cyclone)
	}
}

// A document whose only component is its primary one keeps that component's
// assertions. This is legal CycloneDX, and the ingest fallback that handles it
// used to read half the fields.
func TestMetadataOnlyComponentKeepsItsAssertions(t *testing.T) {
	const metadataOnly = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "metadata": {"component": {
    "bom-ref": "pkg:npm/solo@1.0.0", "type": "application", "name": "solo", "version": "1.0.0",
    "purl": "pkg:npm/solo@1.0.0", "description": "the only component",
    "supplier": {"name": "Solo Supply Co"},
    "hashes": [{"alg": "SHA-256", "content": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}]
  }}
}`
	doc, _, err := UnmarshalAutoJSON([]byte(metadataOnly))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	solo := componentNamed(t, doc, "solo")
	if solo.Supplier == nil || solo.Supplier.Name != "Solo Supply Co" {
		t.Errorf("supplier = %+v", solo.Supplier)
	}
	if !strings.Contains(solo.Description, "only component") {
		t.Errorf("description = %q", solo.Description)
	}
	if len(solo.Digests) == 0 {
		t.Error("the checksum was dropped")
	}
}

// Two components that mint one canonical package URL fold into one node whose
// assertions are the union of both, rather than the first one's alone.
func TestDuplicateComponentsFoldTheirAssertions(t *testing.T) {
	const duplicated = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "components": [
    {"bom-ref": "a", "type": "library", "name": "widget", "version": "1.0.0",
     "purl": "pkg:npm/widget@1.0.0",
     "externalReferences": [{"type": "issue-tracker", "url": "https://one.example/issues"}]},
    {"bom-ref": "b", "type": "library", "name": "widget", "version": "1.0.0",
     "purl": "pkg:npm/widget@1.0.0", "description": "the second says more",
     "supplier": {"name": "Second Supply Co"},
     "externalReferences": [{"type": "chat", "url": "https://two.example/chat"}]}
  ]
}`
	doc, _, err := UnmarshalAutoJSON([]byte(duplicated))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	if graph.Size() != 1 {
		t.Fatalf("size = %d, want the two components folded into one node", graph.Size())
	}
	node := graph.DependencyNodes()[0]
	if !strings.Contains(node.Description, "second says more") {
		t.Errorf("description = %q, want the second component's -- a gap the first left", node.Description)
	}
	if node.Supplier == nil || node.Supplier.Name != "Second Supply Co" {
		t.Errorf("supplier = %+v, want the second component's", node.Supplier)
	}
	var tracker, chat bool
	for _, ref := range node.ExternalReferences {
		tracker = tracker || strings.Contains(ref.Locator, "one.example")
		chat = chat || strings.Contains(ref.Locator, "two.example")
	}
	if !tracker || !chat {
		t.Errorf("references = %+v, want the union of both components'", node.ExternalReferences)
	}
}

// A root component's own supplier is not replaced by configured provenance:
// one names who supplied the component, the other who produced the project.
func TestConfiguredProvenanceDoesNotOverwriteARootSupplier(t *testing.T) {
	doc, _, err := UnmarshalAutoJSON([]byte(supplierRichCycloneDX))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// The lone component is the document's root.
	raw, err := MarshalJSON(doc, TargetSPDX23JSON, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(string(raw), "Widget Supply Co") {
		t.Fatalf("the source supplier is missing:\n%s", raw)
	}

	doc.Provenance = Provenance{Manufacturer: "Operator Ltd"}
	withProvenance, err := MarshalJSON(doc, TargetSPDX23JSON, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export with provenance: %v", err)
	}
	if !strings.Contains(string(withProvenance), "Widget Supply Co") {
		t.Errorf("configured provenance overwrote the component's own supplier:\n%s", withProvenance)
	}
}
