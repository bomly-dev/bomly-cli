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
	if len(component.Digests) == 0 {
		t.Fatalf("%s: checksums lost", where)
	}
	if len(component.CPEs) == 0 {
		t.Fatalf("%s: CPE lost", where)
	}
	var tracker bool
	for _, ref := range component.ExternalReferences {
		if strings.Contains(ref.Locator, "widgets.example/issues") {
			tracker = true
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
