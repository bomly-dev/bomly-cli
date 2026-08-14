package sbom

import (
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// supplierRichCycloneDX is an ingested document asserting the fields Bomly
// itself never invents. A third party asserted them, so a format conversion
// must carry them through rather than silently drop them.
const supplierRichCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {"component": {"bom-ref": "root", "type": "application", "name": "app", "version": "1.0.0"}},
  "components": [
    {
      "bom-ref": "root",
      "type": "application",
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:npm/app@1.0.0"
    },
    {
      "bom-ref": "pkg:npm/left-pad@1.3.0",
      "type": "library",
      "name": "left-pad",
      "version": "1.3.0",
      "purl": "pkg:npm/left-pad@1.3.0",
      "description": "String left padding",
      "publisher": "azer",
      "supplier": {"name": "Example Supplier Inc."},
      "cpe": "cpe:2.3:a:example:left-pad:1.3.0:*:*:*:*:*:*:*",
      "hashes": [{"alg": "SHA-256", "content": "abc123"}],
      "externalReferences": [
        {"type": "distribution", "url": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
        {"type": "vcs", "url": "https://github.com/stevemao/left-pad"},
        {"type": "documentation", "url": "https://example.com/docs"}
      ]
    }
  ],
  "dependencies": [{"ref": "root", "dependsOn": ["pkg:npm/left-pad@1.3.0"]}]
}`

// ingestAndReexport runs the real ingest path: decode, convert to a graph the
// way the SBOM detector does, then rebuild a document from that graph. This is
// what `bomly scan --sbom --path in.cdx.json --format spdx` performs, and it
// is why decoder changes alone are not enough.
func ingestAndReexport(t *testing.T, in []byte, target Target) []byte {
	t.Helper()
	doc, _, err := UnmarshalAutoJSON(in)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	out, err := MarshalDepGraphJSON(graph, target, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal %s: %v", target, err)
	}
	return out
}

func TestIngestedAssertionsSurviveConversionToSPDX(t *testing.T) {
	out := ingestAndReexport(t, []byte(supplierRichCycloneDX), TargetSPDX23JSON)

	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}

	var pkg *v23.Package
	for _, p := range doc.Packages {
		if p != nil && p.PackageName == "left-pad" {
			pkg = p
		}
	}
	if pkg == nil {
		t.Fatal("left-pad missing from spdx output")
	}

	if pkg.PackageSupplier == nil || pkg.PackageSupplier.Supplier != "Example Supplier Inc." {
		t.Fatalf("supplier = %+v, want the ingested value", pkg.PackageSupplier)
	}
	if pkg.PackageDescription != "String left padding" {
		t.Fatalf("description = %q, want the ingested value", pkg.PackageDescription)
	}
	if pkg.PackageOriginator == nil || pkg.PackageOriginator.Originator != "azer" {
		t.Fatalf("originator = %+v, want the ingested publisher", pkg.PackageOriginator)
	}
	if want := "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"; pkg.PackageDownloadLocation != want {
		t.Fatalf("downloadLocation = %q, want %q", pkg.PackageDownloadLocation, want)
	}
	if len(parseSPDXCPEs(pkg.PackageExternalReferences)) != 1 {
		t.Fatal("ingested CPE did not survive conversion")
	}
	if len(pkg.PackageChecksums) != 1 {
		t.Fatalf("ingested checksum did not survive conversion: %+v", pkg.PackageChecksums)
	}
}

func TestIngestedAssertionsSurviveCycloneDXRoundTrip(t *testing.T) {
	out := ingestAndReexport(t, []byte(supplierRichCycloneDX), TargetCycloneDX17JSON)

	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("no components in output")
	}

	var comp *cdx.Component
	for i := range *bom.Components {
		if (*bom.Components)[i].Name == "left-pad" {
			comp = &(*bom.Components)[i]
		}
	}
	if comp == nil {
		t.Fatal("left-pad missing from cyclonedx output")
	}

	if comp.Supplier == nil || comp.Supplier.Name != "Example Supplier Inc." {
		t.Fatalf("supplier = %+v, want the ingested value", comp.Supplier)
	}
	if comp.Description != "String left padding" {
		t.Fatalf("description = %q, want the ingested value", comp.Description)
	}
	if comp.Publisher != "azer" {
		t.Fatalf("publisher = %q, want the ingested value", comp.Publisher)
	}
	if got := externalRefURL(*comp, cdx.ERTypeDistribution); got != "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" {
		t.Fatalf("distribution ref = %q, want the ingested value", got)
	}
	if got := externalRefURL(*comp, cdx.ERTypeVCS); got != "https://github.com/stevemao/left-pad" {
		t.Fatalf("vcs ref = %q, want the ingested value", got)
	}
	// An external reference type Bomly has no opinion about must pass through
	// rather than be dropped as unrecognized.
	if got := externalRefURL(*comp, cdx.ERTypeDocumentation); got != "https://example.com/docs" {
		t.Fatalf("documentation ref = %q, want it preserved verbatim", got)
	}
}

// TestManufacturerWinsOnRootIngestedSupplierSurvivesElsewhere pins the
// precedence rule: the user's configured claim about their own product beats
// an ingested claim on the primary package, and does not erase ingested
// suppliers on dependencies.
func TestManufacturerWinsOnRootIngestedSupplierSurvivesElsewhere(t *testing.T) {
	doc, _, err := UnmarshalAutoJSON([]byte(supplierRichCycloneDX))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	out, err := MarshalDepGraphJSON(graph, TargetSPDX23JSON, BuildOptions{
		ProjectRoot: &ProjectRoot{Name: "demo-project"},
		Provenance:  Provenance{Manufacturer: "Example Org"},
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	var spdxDoc v23.Document
	if err := json.Unmarshal(out, &spdxDoc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}

	for _, p := range spdxDoc.Packages {
		if p == nil || p.PackageSupplier == nil {
			continue
		}
		switch p.PackageName {
		case "left-pad":
			if p.PackageSupplier.Supplier != "Example Supplier Inc." {
				t.Fatalf("dependency supplier = %q, want the ingested value", p.PackageSupplier.Supplier)
			}
		default:
			if p.PackageSupplier.Supplier != "Example Org" {
				t.Fatalf("root supplier = %q, want the configured manufacturer", p.PackageSupplier.Supplier)
			}
		}
	}
}

// TestSPDXNoAssertionSupplierDecodesToAbsent keeps the reserved marker from
// being re-emitted as if it were a real supplier name.
func TestSPDXNoAssertionSupplierDecodesToAbsent(t *testing.T) {
	const in = `{
      "spdxVersion": "SPDX-2.3",
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "doc",
      "documentNamespace": "https://example.com/doc",
      "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: t"]},
      "packages": [{
        "name": "left-pad",
        "SPDXID": "SPDXRef-Package-left-pad",
        "versionInfo": "1.3.0",
        "downloadLocation": "NOASSERTION",
        "supplier": "NOASSERTION",
        "filesAnalyzed": false
      }]
    }`

	doc, _, err := UnmarshalAutoJSON([]byte(in))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, component := range doc.Components {
		if component.Supplier != "" {
			t.Fatalf("NOASSERTION decoded to supplier %q, want absent", component.Supplier)
		}
		if component.ArtifactURL != "" || component.VCSURL != "" || component.RegistryURL != "" {
			t.Fatalf("NOASSERTION decoded to a distribution locator: %+v", component)
		}
	}
}
