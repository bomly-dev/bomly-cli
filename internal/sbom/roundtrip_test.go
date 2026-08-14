package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
	"github.com/spdx/tools-golang/spdx/v2/common"
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
      "supplier": {"name": "Example Supplier Inc.", "url": ["https://supplier.example.com"]},
      "cpe": "cpe:2.3:a:example:left-pad:1.3.0:*:*:*:*:*:*:*",
      "hashes": [{"alg": "SHA-256", "content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
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
	// A CycloneDX publisher is a free string the spec defines as a person or
	// an organization, and SPDX has no untyped originator. Emitting one would
	// assert an entity type the source never made, so the field is omitted
	// rather than guessed. It still round-trips through CycloneDX.
	if pkg.PackageOriginator != nil {
		t.Fatalf("originator = %+v, want it omitted rather than typed by guess", pkg.PackageOriginator)
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
	// A supplier's URL is part of the compliance assertion, so it must not be
	// flattened away to a bare name.
	if comp.Supplier.URL == nil || len(*comp.Supplier.URL) != 1 || (*comp.Supplier.URL)[0] != "https://supplier.example.com" {
		t.Fatalf("supplier url = %+v, want the ingested value preserved", comp.Supplier.URL)
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
	// Stored in the SPDX version-control form: this same value becomes the
	// SPDX PackageDownloadLocation, where a bare https URL would make a
	// repository look like an ordinary package download.
	if got := externalRefURL(*comp, cdx.ERTypeVCS); got != "git+https://github.com/stevemao/left-pad" {
		t.Fatalf("vcs ref = %q, want the normalized ingested value", got)
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

// hostileCycloneDX asserts URLs that must never be re-published: a local path,
// embedded credentials in userinfo and in a query parameter, and a home-page
// style reference pointing at the filesystem.
const hostileCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "bom-ref": "pkg:npm/evil@1.0.0",
      "type": "library",
      "name": "evil",
      "version": "1.0.0",
      "purl": "pkg:npm/evil@1.0.0",
      "externalReferences": [
        {"type": "distribution", "url": "file:///Users/victim/secret/evil-1.0.0.tgz"},
        {"type": "vcs", "url": "https://tok:s3cret@github.com/a/b"},
        {"type": "website", "url": "file:///Users/victim/secret/index.html"},
        {"type": "documentation", "url": "https://docs.example.com/x?token=qu3rysecret"},
        {"type": "chat", "url": "https://chat.example.com/x#fr4gsecret"},
        {"type": "support", "url": "mailto:help@example.com#m41lsecret"},
        {"type": "issue-tracker", "url": "https://issues.example.com/evil"}
      ]
    }
  ]
}`

// TestIngestedUnsafeURLsAreNotRepublished is the counterpart to the
// detector-side leak test. An ingested document is untrusted input, so its
// URLs must pass the same gate a lockfile value does — otherwise a hostile or
// merely careless SBOM could launder a credential or a local path into output
// Bomly publishes.
func TestIngestedUnsafeURLsAreNotRepublished(t *testing.T) {
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
		out := ingestAndReexport(t, []byte(hostileCycloneDX), target)
		rendered := string(out)

		// Each secret is unique so a gate that rejects one form cannot mask
		// another: the query case must not be what stops the fragment case.
		for _, forbidden := range []string{
			"file://", "/Users/victim", "s3cret", "tok:", "token=",
			"qu3rysecret", "fr4gsecret", "m41lsecret",
		} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("%s output republished %q from an ingested document:\n%s", target, forbidden, rendered)
			}
		}

		// The one safe reference must still survive, so the gate is filtering
		// rather than discarding everything.
		if target == TargetCycloneDX17JSON && !strings.Contains(rendered, "https://issues.example.com/evil") {
			t.Fatalf("cyclonedx output dropped the safe reference:\n%s", rendered)
		}
	}
}

// TestSPDXSourceInfoRepositoryIsGated covers the other direction of the
// ingest gate: a repository recovered from SPDX PackageSourceInfo is
// re-published in both formats, so it needs the same validation as any other
// ingested URL.
func TestSPDXSourceInfoRepositoryIsGated(t *testing.T) {
	cases := []struct {
		name       string
		sourceInfo string
		wantRepo   string
	}{
		{"credentials", "Source repository: https://user:sp3csecret@github.com/org/repo", ""},
		{"local path", "Source repository: file:///Users/victim/repo", ""},
		{"query", "Source repository: https://github.com/org/repo?token=sp3csecret", ""},
		{"safe", "Source repository: https://github.com/org/repo", "https://github.com/org/repo"},
		{"unmarked prose", "Built from an internal mirror", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := parseSPDXSourceInfo(tc.sourceInfo); got != tc.wantRepo {
				t.Fatalf("parseSPDXSourceInfo(%q) = %q, want %q", tc.sourceInfo, got, tc.wantRepo)
			}
		})
	}

	const hostile = `{
      "spdxVersion": "SPDX-2.3",
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "doc",
      "documentNamespace": "https://example.com/doc",
      "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: t"]},
      "packages": [{
        "name": "evil",
        "SPDXID": "SPDXRef-Package-evil",
        "versionInfo": "1.0.0",
        "downloadLocation": "NOASSERTION",
        "sourceInfo": "Source repository: https://user:sp3csecret@github.com/org/repo",
        "filesAnalyzed": false
      }]
    }`

	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
		out := ingestAndReexport(t, []byte(hostile), target)
		if strings.Contains(string(out), "sp3csecret") {
			t.Fatalf("%s republished a credential from SPDX sourceInfo:\n%s", target, out)
		}
	}
}

// TestUnknownExternalReferenceTypeIsMappedToOther keeps an ingested document
// from producing schema-invalid output. The CycloneDX library's
// version-downgrade pass only rewrites types it recognizes, so an arbitrary
// string would otherwise be emitted verbatim against a closed enum.
func TestUnknownExternalReferenceTypeIsMappedToOther(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0",
        "type": "library",
        "name": "a",
        "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [
          {"type": "totally-made-up", "url": "https://example.com/x"},
          {"type": "issue-tracker", "url": "https://example.com/issues"}
        ]
      }]
    }`

	out := ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON)
	if strings.Contains(string(out), "totally-made-up") {
		t.Fatalf("unknown external reference type was emitted verbatim:\n%s", out)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	comp := (*bom.Components)[0]
	if got := externalRefURL(comp, cdx.ERTypeOther); got != "https://example.com/x" {
		t.Fatalf("expected the unknown type remapped to \"other\" with its URL kept, got %q", got)
	}
	if got := externalRefURL(comp, cdx.ERTypeIssueTracker); got != "https://example.com/issues" {
		t.Fatalf("known type was not preserved, got %q", got)
	}
}

// TestPersonSupplierIsNotRecastAsOrganization covers the counterpart of the
// publisher rule: CycloneDX has no person-valued supplier, so an explicit
// SPDX "Person:" supplier must not be relabelled.
func TestPersonSupplierIsNotRecastAsOrganization(t *testing.T) {
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
        "supplier": "Person: Alice",
        "filesAnalyzed": false
      }]
    }`

	cdxOut := ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON)
	if strings.Contains(string(cdxOut), "Alice") {
		t.Fatalf("a person supplier was recast as a CycloneDX organization:\n%s", cdxOut)
	}

	// SPDX represents the type natively, so it must survive there.
	spdxOut := ingestAndReexport(t, []byte(in), TargetSPDX23JSON)
	var doc v23.Document
	if err := json.Unmarshal(spdxOut, &doc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	for _, p := range doc.Packages {
		if p == nil || p.PackageName != "left-pad" {
			continue
		}
		if p.PackageSupplier == nil || p.PackageSupplier.SupplierType != "Person" || p.PackageSupplier.Supplier != "Alice" {
			t.Fatalf("spdx supplier = %+v, want Person: Alice preserved", p.PackageSupplier)
		}
		return
	}
	t.Fatal("left-pad missing from spdx output")
}

// TestDuplicatePURLAssertionsAreMerged covers an ingest shape the codec
// already supports: several component IDs mapping to one PURL. Only the first
// becomes a graph node, so a later duplicate's assertions must be folded in
// rather than discarded with it.
func TestDuplicatePURLAssertionsAreMerged(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{
				ID:      "first",
				Name:    "certifi",
				Version: "2026.4.22",
				PURL:    "pkg:pypi/certifi@2026.4.22",
				CPEs:    []string{"cpe:2.3:a:x:certifi:2026.4.22:*:*:*:*:*:*:*"},
			},
			{
				ID:          "second",
				Name:        "certifi",
				Version:     "2026.4.22",
				PURL:        "pkg:pypi/certifi@2026.4.22",
				Supplier:    "Example Supplier Inc.",
				Description: "Root certificates",
				ArtifactURL: "https://files.pythonhosted.org/x/certifi-2026.4.22-py3-none-any.whl",
				Digests:     []Digest{{Algorithm: "sha256", Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
			},
		},
		Dependencies: []Dependency{{Ref: "first", DependsOn: []string{"second"}}},
	}

	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	out, err := MarshalDepGraphJSON(graph, TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var spdxDoc v23.Document
	if err := json.Unmarshal(out, &spdxDoc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(spdxDoc.Packages) != 1 {
		t.Fatalf("expected one merged package, got %d", len(spdxDoc.Packages))
	}
	pkg := spdxDoc.Packages[0]
	if pkg.PackageSupplier == nil || pkg.PackageSupplier.Supplier != "Example Supplier Inc." {
		t.Fatalf("supplier from the duplicate was dropped: %+v", pkg.PackageSupplier)
	}
	if pkg.PackageDescription != "Root certificates" {
		t.Fatalf("description from the duplicate was dropped: %q", pkg.PackageDescription)
	}
	if !strings.HasSuffix(pkg.PackageDownloadLocation, ".whl") {
		t.Fatalf("download location from the duplicate was dropped: %q", pkg.PackageDownloadLocation)
	}
	if len(pkg.PackageChecksums) != 1 {
		t.Fatalf("digest from the duplicate was dropped: %+v", pkg.PackageChecksums)
	}
	if len(parseSPDXCPEs(pkg.PackageExternalReferences)) != 1 {
		t.Fatal("CPE from the first component was lost in the merge")
	}
}

// TestIngestedVCSFragmentCredentialIsNotRepublished covers the version-control
// normalization path, which is exempt from the query/fragment gate. A fragment
// there is treated as a revision, so it must be commit-shaped rather than
// merely character-safe — an access token satisfies the looser rule.
func TestIngestedVCSFragmentCredentialIsNotRepublished(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0",
        "type": "library",
        "name": "a",
        "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [
          {"type": "vcs", "url": "https://github.com/org/repo#ghp_abcd1234"}
        ]
      }]
    }`

	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
		out := ingestAndReexport(t, []byte(in), target)
		rendered := string(out)
		if strings.Contains(rendered, "ghp_abcd1234") {
			t.Fatalf("%s republished a token from a vcs fragment:\n%s", target, rendered)
		}
		// The repository itself is still a legitimate assertion.
		if !strings.Contains(rendered, "github.com/org/repo") {
			t.Fatalf("%s dropped the repository along with the token:\n%s", target, rendered)
		}
	}
}

// TestVCSSurvivesWhenArtifactOwnsDownloadLocation covers a component asserting
// both a distribution and a vcs reference. The artifact takes SPDX's single
// download-location field, so the repository has to land in PackageSourceInfo
// rather than being dropped.
func TestVCSSurvivesWhenArtifactOwnsDownloadLocation(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0",
        "type": "library",
        "name": "a",
        "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [
          {"type": "distribution", "url": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
          {"type": "vcs", "url": "https://github.com/org/repo"}
        ]
      }]
    }`

	out := ingestAndReexport(t, []byte(in), TargetSPDX23JSON)
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range doc.Packages {
		if p == nil || p.PackageName != "a" {
			continue
		}
		if p.PackageDownloadLocation != "https://registry.npmjs.org/a/-/a-1.0.0.tgz" {
			t.Fatalf("downloadLocation = %q, want the artifact", p.PackageDownloadLocation)
		}
		if !strings.Contains(p.PackageSourceInfo, "github.com/org/repo") {
			t.Fatalf("sourceInfo = %q, want the repository preserved", p.PackageSourceInfo)
		}
		return
	}
	t.Fatal("component missing from output")
}

// TestPrimaryComponentAssertionsMergeFromMetadata covers a producer that lists
// the primary component in the inventory but puts its assertions only on
// metadata.component.
func TestPrimaryComponentAssertionsMergeFromMetadata(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "metadata": {"component": {
        "bom-ref": "root", "type": "application", "name": "app", "version": "1.0.0",
        "purl": "pkg:npm/app@1.0.0",
        "description": "The scanned application",
        "supplier": {"name": "Example Supplier Inc."}
      }},
      "components": [
        {"bom-ref": "root", "type": "application", "name": "app", "version": "1.0.0", "purl": "pkg:npm/app@1.0.0"},
        {"bom-ref": "pkg:npm/dep@1.0.0", "type": "library", "name": "dep", "version": "1.0.0", "purl": "pkg:npm/dep@1.0.0"}
      ],
      "dependencies": [{"ref": "root", "dependsOn": ["pkg:npm/dep@1.0.0"]}]
    }`

	out := ingestAndReexport(t, []byte(in), TargetSPDX23JSON)
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range doc.Packages {
		if p == nil || p.PackageName != "app" {
			continue
		}
		if p.PackageDescription != "The scanned application" {
			t.Fatalf("description = %q, want it merged from metadata.component", p.PackageDescription)
		}
		if p.PackageSupplier == nil || p.PackageSupplier.Supplier != "Example Supplier Inc." {
			t.Fatalf("supplier = %+v, want it merged from metadata.component", p.PackageSupplier)
		}
		return
	}
	t.Fatal("app missing from output")
}

// TestMalformedIngestedDigestIsDropped keeps a bogus hash out of the output.
// The encoders filter on algorithm only, so an unvalidated value would be
// re-emitted verbatim: schema-invalid, and a false integrity assertion.
func TestMalformedIngestedDigestIsDropped(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0",
        "type": "library",
        "name": "a",
        "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "hashes": [
          {"alg": "SHA-256", "content": "not-a-hash"},
          {"alg": "BLAKE2b-256", "content": "ab"},
          {"alg": "SHA-256", "content": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
        ]
      }]
    }`

	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
		out := ingestAndReexport(t, []byte(in), target)
		if strings.Contains(string(out), "not-a-hash") {
			t.Fatalf("%s republished a malformed digest:\n%s", target, out)
		}
		// Hex but far too short. Every algorithm the encoders accept needs a
		// length entry, or this passes validation unchecked.
		if strings.Contains(string(out), `"ab"`) {
			t.Fatalf("%s republished a short BLAKE2b digest:\n%s", target, out)
		}
		if !strings.Contains(string(out), "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc") {
			t.Fatalf("%s dropped the valid digest alongside the malformed one:\n%s", target, out)
		}
	}
}

// TestIngestedReferenceCommentsArePreserved covers comments on the two
// reference kinds Bomly classifies. Replacing a producer's comment with
// Bomly's own could contradict what the source asserted.
func TestIngestedReferenceCommentsArePreserved(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0",
        "type": "library",
        "name": "a",
        "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [
          {"type": "distribution", "url": "https://reg.example/", "comment": "Exact authenticated download endpoint"},
          {"type": "vcs", "url": "https://github.com/org/repo", "comment": "Mirror of the upstream repository"}
        ]
      }]
    }`

	out := ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON)
	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	comp := (*bom.Components)[0]
	if comp.ExternalReferences == nil {
		t.Fatal("no external references in output")
	}
	for _, ref := range *comp.ExternalReferences {
		switch ref.Type {
		case cdx.ERTypeDistribution:
			if ref.Comment != "Exact authenticated download endpoint" {
				t.Fatalf("distribution comment = %q, want the producer's own text", ref.Comment)
			}
		case cdx.ERTypeVCS:
			if ref.Comment != "Mirror of the upstream repository" {
				t.Fatalf("vcs comment = %q, want the producer's own text", ref.Comment)
			}
		}
	}
}

// TestSPDXSummaryAndDescriptionStaySeparate covers two fields SPDX represents
// distinctly. Folding the summary into the description moves it to a
// semantically different field and loses it entirely when both are present.
func TestSPDXSummaryAndDescriptionStaySeparate(t *testing.T) {
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
        "summary": "Pads a string",
        "description": "A longer explanation of the padding behaviour",
        "filesAnalyzed": false
      }]
    }`

	out := ingestAndReexport(t, []byte(in), TargetSPDX23JSON)
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range doc.Packages {
		if p == nil || p.PackageName != "left-pad" {
			continue
		}
		if p.PackageSummary != "Pads a string" {
			t.Fatalf("summary = %q, want it preserved separately", p.PackageSummary)
		}
		if p.PackageDescription != "A longer explanation of the padding behaviour" {
			t.Fatalf("description = %q, want it preserved separately", p.PackageDescription)
		}
		return
	}
	t.Fatal("left-pad missing from output")
}

// TestCPE22ReferenceTypeIsPreserved keeps an SPDX round trip from relabelling
// a CPE 2.2 locator as 2.3 without converting its syntax.
func TestCPE22ReferenceTypeIsPreserved(t *testing.T) {
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
        "filesAnalyzed": false,
        "externalRefs": [
          {"referenceCategory": "SECURITY", "referenceType": "cpe22Type", "referenceLocator": "cpe:/a:vendor:product:1.0"},
          {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}
        ]
      }]
    }`

	out := ingestAndReexport(t, []byte(in), TargetSPDX23JSON)
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	byLocator := map[string]string{}
	for _, p := range doc.Packages {
		if p == nil {
			continue
		}
		for _, ref := range p.PackageExternalReferences {
			if ref != nil {
				byLocator[ref.Locator] = ref.RefType
			}
		}
	}
	if got := byLocator["cpe:/a:vendor:product:1.0"]; got != "cpe22Type" {
		t.Fatalf("cpe 2.2 locator emitted as %q, want cpe22Type", got)
	}
	if got := byLocator["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]; got != "cpe23Type" {
		t.Fatalf("cpe 2.3 locator emitted as %q, want cpe23Type", got)
	}
}

// TestUrnExternalReferenceSurvives covers a valid non-HTTP IRI. CycloneDX
// external-reference URLs are IRI references, so a "bom" reference to a
// urn:uuid must not be dropped as an unknown scheme.
func TestUrnExternalReferenceSurvives(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0",
        "type": "library",
        "name": "a",
        "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [
          {"type": "bom", "url": "urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301"}
        ]
      }]
    }`

	out := ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON)
	if !strings.Contains(string(out), "urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301") {
		t.Fatalf("a valid urn external reference was dropped:\n%s", out)
	}
}

// TestDuplicatePURLExternalRefsAreUnioned covers reference sets on two
// components sharing a PURL. They are a set, not a single assertion, so a
// fill-gaps merge would drop the second list whenever the first had any.
func TestDuplicatePURLExternalRefsAreUnioned(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{
				ID: "first", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0",
				ExternalRefs: []ExternalRef{{Type: "website", URL: "https://example.com/site"}},
			},
			{
				ID: "second", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0",
				ExternalRefs: []ExternalRef{{Type: "documentation", URL: "https://example.com/docs"}},
			},
		},
		Dependencies: []Dependency{{Ref: "first", DependsOn: []string{"second"}}},
	}

	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	out, err := MarshalDepGraphJSON(graph, TargetCycloneDX17JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{"https://example.com/site", "https://example.com/docs"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("merged component lost %q:\n%s", want, out)
		}
	}
}

// TestPrimaryComponentExternalRefsAreUnioned is the same set semantics for a
// primary component described in both metadata.component and the inventory.
func TestPrimaryComponentExternalRefsAreUnioned(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "metadata": {"component": {
        "bom-ref": "root", "type": "application", "name": "app", "version": "1.0.0",
        "purl": "pkg:npm/app@1.0.0",
        "externalReferences": [{"type": "documentation", "url": "https://example.com/docs"}]
      }},
      "components": [
        {"bom-ref": "root", "type": "application", "name": "app", "version": "1.0.0", "purl": "pkg:npm/app@1.0.0",
         "externalReferences": [{"type": "website", "url": "https://example.com/site"}]},
        {"bom-ref": "pkg:npm/dep@1.0.0", "type": "library", "name": "dep", "version": "1.0.0", "purl": "pkg:npm/dep@1.0.0"}
      ],
      "dependencies": [{"ref": "root", "dependsOn": ["pkg:npm/dep@1.0.0"]}]
    }`

	out := ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON)
	for _, want := range []string{"https://example.com/site", "https://example.com/docs"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("primary component lost %q:\n%s", want, out)
		}
	}
}

// TestGitTransportVCSReferenceSurvives covers a git:// repository reference.
// isPublishableReferenceURL already accepts that transport, so the narrower
// VCS path must not reject it and drop the repository.
func TestGitTransportVCSReferenceSurvives(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0",
        "type": "library",
        "name": "a",
        "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [{"type": "vcs", "url": "git://github.com/org/repo"}]
      }]
    }`

	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
		out := ingestAndReexport(t, []byte(in), target)
		if !strings.Contains(string(out), "github.com/org/repo") {
			t.Fatalf("%s dropped a git:// repository reference:\n%s", target, out)
		}
	}
}

// TestMultipleDistributionReferencesArePreserved covers a component listing
// several download mirrors. The neutral model has one artifact slot, so the
// extras have to be kept rather than overwriting each other.
func TestMultipleDistributionReferencesArePreserved(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0",
        "type": "library",
        "name": "a",
        "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [
          {"type": "distribution", "url": "https://primary.example/a-1.0.0.tgz"},
          {"type": "distribution", "url": "https://mirror.example/a-1.0.0.tgz"}
        ]
      }]
    }`

	out := ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON)
	for _, want := range []string{"https://primary.example/a-1.0.0.tgz", "https://mirror.example/a-1.0.0.tgz"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("distribution mirror %q was overwritten:\n%s", want, out)
		}
	}
}

// TestPrimaryComponentDigestsAreUnioned covers set-valued integrity data on a
// component described in both metadata.component and the inventory.
func TestPrimaryComponentDigestsAreUnioned(t *testing.T) {
	// Correct hex widths for each algorithm: a wrong-width value would be
	// dropped by digest validation, and the test would then pass without ever
	// exercising the union.
	inventoryHash := strings.Repeat("a", 64) // SHA-256
	metadataHash := strings.Repeat("b", 128) // SHA-512
	in := `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "metadata": {"component": {
        "bom-ref": "root", "type": "application", "name": "app", "version": "1.0.0",
        "purl": "pkg:npm/app@1.0.0",
        "hashes": [{"alg": "SHA-512", "content": "` + metadataHash + `"}]
      }},
      "components": [
        {"bom-ref": "root", "type": "application", "name": "app", "version": "1.0.0", "purl": "pkg:npm/app@1.0.0",
         "hashes": [{"alg": "SHA-256", "content": "` + inventoryHash + `"}]},
        {"bom-ref": "pkg:npm/dep@1.0.0", "type": "library", "name": "dep", "version": "1.0.0", "purl": "pkg:npm/dep@1.0.0"}
      ],
      "dependencies": [{"ref": "root", "dependsOn": ["pkg:npm/dep@1.0.0"]}]
    }`

	out := ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON)
	for name, want := range map[string]string{
		"inventory": inventoryHash,
		"metadata":  metadataHash,
	} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("%s hash was discarded by the merge:\n%s", name, out)
		}
	}
}

// TestSPDXHomePageSurvivesSPDXRoundTrip covers a field SPDX represents
// exactly, which an earlier revision decoded but never re-emitted.
func TestSPDXHomePageSurvivesSPDXRoundTrip(t *testing.T) {
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
        "downloadLocation": "https://repo.example/download/left-pad",
        "homepage": "https://left-pad.example.com",
        "checksums": [{"algorithm": "SHA3-256", "checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
        "filesAnalyzed": false
      }]
    }`

	out := ingestAndReexport(t, []byte(in), TargetSPDX23JSON)
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	for _, p := range doc.Packages {
		if p == nil || p.PackageName != "left-pad" {
			continue
		}
		if p.PackageHomePage != "https://left-pad.example.com" {
			t.Fatalf("homepage = %q, want it preserved", p.PackageHomePage)
		}
		// An exact endpoint with no archive suffix: the source document
		// declared it a download location, so it must not be demoted.
		if p.PackageDownloadLocation != "https://repo.example/download/left-pad" {
			t.Fatalf("downloadLocation = %q, want the asserted value", p.PackageDownloadLocation)
		}
		if len(p.PackageChecksums) != 1 {
			t.Fatalf("SHA3-256 checksum did not survive: %+v", p.PackageChecksums)
		}
		// Assert both fields: a length check alone would not notice the
		// algorithm degrading to a different family on the way through.
		if got := p.PackageChecksums[0]; got.Algorithm != common.SHA3_256 || got.Value != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			t.Fatalf("checksum = %+v, want SHA3-256 with the asserted 64-character hex value", got)
		}
		return
	}
	t.Fatal("left-pad missing from output")
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

// TestIsValidCPE guards the package-identity assertion. An ingested document
// can label any string cpe23Type, and an unchecked value is republished as an
// SPDX security reference and CycloneDX's `cpe` field.
func TestIsValidCPE(t *testing.T) {
	valid := []string{
		"cpe:2.3:a:example:left-pad:1.3.0:*:*:*:*:*:*:*",
		"cpe:2.3:o:vendor:os:1.0:-:*:*:*:*:*:*",
		`cpe:2.3:a:ven\:dor:prod:1.0:*:*:*:*:*:*:*`,
		"cpe:/a:vendor:product:1.0",
		"cpe:/o:vendor:os",
		// Wildcards inside a value are legal and common; rejecting them
		// would drop real identity data.
		"cpe:2.3:a:vendor:product:1.3.*:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor:node.js:10.0:*:*:*:*:*:*:*",
	}
	for _, value := range valid {
		if !isValidCPE(value) {
			t.Fatalf("isValidCPE(%q) = false, want a well-formed CPE accepted", value)
		}
	}

	invalid := []string{
		"not-a-cpe", "", "   ",
		"cpe:2.3:a:example:left-pad",                           // too few components
		"cpe:2.3:a:example:left-pad:1.3.0:*:*:*:*:*:*:*:extra", // too many
		"cpe:2.3:z:vendor:product:1.0:*:*:*:*:*:*:*",           // bad part
		"cpe:/z:vendor:product",                                // bad part
		"cpe:/a:b:c:d:e:f:g:h",                                 // too many
		"https://example.com",
		// Component-level checks: a correct field count is not enough.
		"cpe:2.3:a:vendor with space:product:*:*:*:*:*:*:*:*", // unescaped whitespace
		"cpe:2.3::vendor:product:*:*:*:*:*:*:*:*",             // empty part
		"cpe:2.3:a:vendor:prod<uct:*:*:*:*:*:*:*:*",           // unescaped reserved punctuation
		"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:" + `x\`,    // trailing lone backslash
		"cpe:2.3:a:vendor::*:*:*:*:*:*:*:*",                   // empty component
		"cpe:/a:vendor with space:product",                    // whitespace in the uri binding
	}
	for _, value := range invalid {
		if isValidCPE(value) {
			t.Fatalf("isValidCPE(%q) = true, want it rejected", value)
		}
	}
}

// TestMalformedCPEIsNotRepublished is the end-to-end counterpart.
func TestMalformedCPEIsNotRepublished(t *testing.T) {
	const in = `{
      "spdxVersion": "SPDX-2.3",
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "doc",
      "documentNamespace": "https://example.com/doc",
      "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: t"]},
      "packages": [{
        "name": "a", "SPDXID": "SPDXRef-Package-a", "versionInfo": "1.0.0",
        "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
        "externalRefs": [
          {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "not-a-cpe"},
          {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"}
        ]
      }]
    }`

	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
		out := ingestAndReexport(t, []byte(in), target)
		if strings.Contains(string(out), "not-a-cpe") {
			t.Fatalf("%s republished a malformed CPE:\n%s", target, out)
		}
		if !strings.Contains(string(out), "cpe:2.3:a:v:p:1.0") {
			t.Fatalf("%s dropped the valid CPE alongside it:\n%s", target, out)
		}
	}
}

// TestPinnedVCSSourceInfoKeepsItsSyntax covers a component with both an
// artifact and a pinned repository. Stripping "git+" would turn the revision
// into part of the URL path, yielding an address that does not exist and that
// re-ingests cleanly as if it did.
func TestPinnedVCSSourceInfoKeepsItsSyntax(t *testing.T) {
	doc := &Document{
		Components: []Component{{
			ID: "a", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0",
			ArtifactURL: "https://reg.example/a-1.0.0.tgz",
			VCSURL:      "git+https://github.com/org/repo@deadbeef",
		}},
	}
	out, err := MarshalDepGraphJSON(mustGraphFromDoc(t, doc), TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var spdxDoc v23.Document
	if err := json.Unmarshal(out, &spdxDoc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range spdxDoc.Packages {
		if p == nil || p.PackageName != "a" {
			continue
		}
		if !strings.Contains(p.PackageSourceInfo, "git+https://github.com/org/repo@deadbeef") {
			t.Fatalf("sourceInfo = %q, want the version-control form intact", p.PackageSourceInfo)
		}
		// And it must survive a re-ingest rather than decoding as a bare URL.
		if _, vcs := parseSPDXSourceInfo(p.PackageSourceInfo); vcs != "git+https://github.com/org/repo@deadbeef" {
			t.Fatalf("re-ingested vcs = %q, want the pinned locator", vcs)
		}
		return
	}
	t.Fatal("component missing from output")
}

// mustGraphFromDoc converts a neutral document to a graph for export tests.
func mustGraphFromDoc(t *testing.T, doc *Document) *sdk.Graph {
	t.Helper()
	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	return graph
}

// TestSetValuedAssertionsSurviveDuplicateMerge is the sweep's regression net.
// Every set-valued field on a component described twice must union rather than
// let one copy win; this repeatedly turned up one field at a time in review.
func TestSetValuedAssertionsSurviveDuplicateMerge(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "metadata": {"component": {
        "bom-ref": "root", "type": "application", "name": "app", "version": "1.0.0",
        "purl": "pkg:npm/app@1.0.0",
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "supplier": {"name": "Acme", "url": ["https://second.example"]},
        "externalReferences": [{"type": "documentation", "url": "https://docs.example"}]
      }},
      "components": [
        {"bom-ref": "root", "type": "application", "name": "app", "version": "1.0.0", "purl": "pkg:npm/app@1.0.0",
         "licenses": [{"license": {"id": "MIT"}}],
         "supplier": {"name": "Acme", "url": ["https://first.example"]},
         "externalReferences": [{"type": "website", "url": "https://site.example"}]},
        {"bom-ref": "pkg:npm/dep@1.0.0", "type": "library", "name": "dep", "version": "1.0.0", "purl": "pkg:npm/dep@1.0.0"}
      ],
      "dependencies": [{"ref": "root", "dependsOn": ["pkg:npm/dep@1.0.0"]}]
    }`

	out := string(ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON))
	for name, want := range map[string]string{
		"inventory license":      "MIT",
		"metadata license":       "Apache-2.0",
		"inventory supplier url": "https://first.example",
		"metadata supplier url":  "https://second.example",
		"inventory reference":    "https://site.example",
		"metadata reference":     "https://docs.example",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("%s was discarded by the merge:\n%s", name, out)
		}
	}
}

// TestMultipleVCSReferencesArePreserved mirrors the distribution-mirror case:
// CycloneDX types vcs as an array, so extra repositories must not overwrite.
func TestMultipleVCSReferencesArePreserved(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0", "type": "library", "name": "a", "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [
          {"type": "vcs", "url": "https://github.com/org/primary"},
          {"type": "vcs", "url": "https://gitlab.com/org/mirror"}
        ]
      }]
    }`

	out := string(ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON))
	for _, want := range []string{"github.com/org/primary", "gitlab.com/org/mirror"} {
		if !strings.Contains(out, want) {
			t.Fatalf("vcs mirror %q was overwritten:\n%s", want, out)
		}
	}
}

// TestIngestedDistributionKeepsBenignQuery covers a source-declared download
// with a benign query. The detector-oriented classifier drops every query,
// which is right for a lockfile value and wrong for an asserted one.
func TestIngestedDistributionKeepsBenignQuery(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0", "type": "library", "name": "a", "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [
          {"type": "distribution", "url": "https://repo.example/download?id=123"}
        ]
      }]
    }`

	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
		out := string(ingestAndReexport(t, []byte(in), target))
		if !strings.Contains(out, "https://repo.example/download?id=123") {
			t.Fatalf("%s dropped an asserted download with a benign query:\n%s", target, out)
		}
	}

	// A credential-bearing query is still rejected on the same path.
	hostile := strings.Replace(in, "?id=123", "?token=s3cret", 1)
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
		if out := string(ingestAndReexport(t, []byte(hostile), target)); strings.Contains(out, "s3cret") {
			t.Fatalf("%s republished a credential query:\n%s", target, out)
		}
	}
}

// TestSPDXNoneDownloadLocationIsPreserved keeps two distinct SPDX assertions
// apart: NONE says the package is not downloadable, NOASSERTION says the
// producer made no claim.
func TestSPDXNoneDownloadLocationIsPreserved(t *testing.T) {
	const in = `{
      "spdxVersion": "SPDX-2.3",
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "doc",
      "documentNamespace": "https://example.com/doc",
      "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: t"]},
      "packages": [
        {"name": "none-pkg", "SPDXID": "SPDXRef-a", "versionInfo": "1.0.0", "downloadLocation": "NONE", "filesAnalyzed": false},
        {"name": "noassert-pkg", "SPDXID": "SPDXRef-b", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false}
      ]
    }`

	out := ingestAndReexport(t, []byte(in), TargetSPDX23JSON)
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := map[string]string{}
	for _, p := range doc.Packages {
		if p != nil {
			got[p.PackageName] = p.PackageDownloadLocation
		}
	}
	if got["none-pkg"] != "NONE" {
		t.Fatalf("NONE became %q, want the assertion preserved", got["none-pkg"])
	}
	if got["noassert-pkg"] != "NOASSERTION" {
		t.Fatalf("NOASSERTION became %q", got["noassert-pkg"])
	}
}

// TestVCSLocatorRevisionIsValidated covers an already-rendered
// "git+…@<revision>" locator. The suffix parses as part of the URL path, so
// the scheme and userinfo checks never see it — an earlier version returned
// such a locator unchanged and republished the token in it.
func TestVCSLocatorRevisionIsValidated(t *testing.T) {
	cases := []struct{ in, want string }{
		{"git+https://github.com/org/repo@deadbeef", "git+https://github.com/org/repo@deadbeef"},
		{"git+https://github.com/org/repo@v1.2.3", "git+https://github.com/org/repo@v1.2.3"},
		// Token-shaped revision: the repository survives, the secret does not.
		{"git+https://github.com/org/repo@ghp_abcd1234", "git+https://github.com/org/repo"},
		{"git+https://github.com/org/repo@glpat-Abc123", "git+https://github.com/org/repo"},
		{"git+https://tok:s3cret@github.com/org/repo", ""},
		// Userinfo with no path: splitting on "@" before parsing read
		// "ghp_secret" as the host and "github.com" as a revision, then
		// rebuilt the original credential.
		{"git+https://ghp_secret@github.com", ""},
		{"git+https://ghp_secret@github.com/org/repo", ""},
		{"git+https://user@github.com/org/repo", ""},
		{"git+file:///Users/victim/repo", ""},
		{"https://github.com/org/repo", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := validatedVCSLocator(tc.in); got != tc.want {
			t.Fatalf("validatedVCSLocator(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestVCSSourceInfoTokenIsNotRepublished is the end-to-end counterpart.
func TestVCSSourceInfoTokenIsNotRepublished(t *testing.T) {
	const in = `{
      "spdxVersion": "SPDX-2.3",
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "doc",
      "documentNamespace": "https://example.com/doc",
      "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: t"]},
      "packages": [{
        "name": "a", "SPDXID": "SPDXRef-a", "versionInfo": "1.0.0",
        "downloadLocation": "https://reg.example/a-1.0.0.tgz", "filesAnalyzed": false,
        "sourceInfo": "Source repository: git+https://github.com/org/repo@ghp_abcd1234"
      }]
    }`

	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
		out := string(ingestAndReexport(t, []byte(in), target))
		if strings.Contains(out, "ghp_abcd1234") {
			t.Fatalf("%s republished a token from a rendered VCS locator:\n%s", target, out)
		}
		if !strings.Contains(out, "github.com/org/repo") {
			t.Fatalf("%s dropped the repository along with the token:\n%s", target, out)
		}
	}
}

// Realistic CPEs drawn from NVD-style identifiers, to confirm the stricter
// component validation does not reject genuine identity data.
func TestRealWorldCPEsAccepted(t *testing.T) {
	for _, value := range []string{
		"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
		"cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*",
		"cpe:2.3:a:nodejs:node.js:16.13.0:*:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:5.15.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:facebook:react:18.2.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:python:cpython:3.11.0:rc1:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:.net:6.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor:product:1.3.*:*:*:*:*:*:*:*",
		"cpe:2.3:h:cisco:asr_9000:-:*:*:*:*:*:*:*",
		"cpe:2.3:a:gnu:glibc:2.35:*:*:*:*:*:*:*",
		`cpe:2.3:a:acme:c\+\+_library:1.0:*:*:*:*:*:*:*`,
		"cpe:/a:apache:log4j:2.14.1",
		"cpe:/o:linux:linux_kernel:5.15.0",
	} {
		if !isValidCPE(value) {
			t.Errorf("real-world CPE rejected: %q", value)
		}
	}
}

// TestSupplierContactsAndReferenceHashesSurvive covers two assertions the
// producer already published: the supplier's contact entries and the integrity
// hash attached to an external reference. Preserving them republishes nothing
// new, and CycloneDX represents both directly.
func TestSupplierContactsAndReferenceHashesSurvive(t *testing.T) {
	hash := strings.Repeat("e", 64)
	in := `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0", "type": "library", "name": "a", "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "supplier": {
          "name": "Acme",
          "contact": [{"name": "Security Team", "email": "security@acme.example"}]
        },
        "externalReferences": [
          {"type": "documentation", "url": "https://docs.example/page",
           "hashes": [{"alg": "SHA-256", "content": "` + hash + `"}]}
        ]
      }]
    }`

	raw := ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON)
	for name, want := range map[string]string{
		"contact name":  "Security Team",
		"contact email": "security@acme.example",
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("%s was dropped:\n%s", name, raw)
		}
	}

	// Assert the reference hash structurally. A substring match on the value
	// would still pass if the algorithm were relabelled underneath it.
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	comp := (*bom.Components)[0]
	if comp.ExternalReferences == nil {
		t.Fatalf("no external references in output:\n%s", raw)
	}
	found := false
	for _, ref := range *comp.ExternalReferences {
		if ref.Type != cdx.ERTypeDocumentation || ref.Hashes == nil {
			continue
		}
		for _, h := range *ref.Hashes {
			if h.Algorithm != cdx.HashAlgoSHA256 || h.Value != hash {
				t.Fatalf("reference hash = %+v, want SHA-256 with the asserted value", h)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("the reference integrity assertion was dropped:\n%s", raw)
	}
}

// TestBenignQueryOnGeneralReferenceSurvives covers references other than
// distribution. They are source-declared too, so a benign query is part of the
// assertion while a credential-shaped one is not.
func TestBenignQueryOnGeneralReferenceSurvives(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0", "type": "library", "name": "a", "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [
          {"type": "documentation", "url": "https://docs.example/page?version=1"},
          {"type": "website", "url": "https://site.example/x?client_secret=s3cret"}
        ]
      }]
    }`

	out := string(ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON))
	if !strings.Contains(out, "https://docs.example/page?version=1") {
		t.Fatalf("a benign query on a general reference was dropped:\n%s", out)
	}
	if strings.Contains(out, "s3cret") {
		t.Fatalf("a client_secret query was republished:\n%s", out)
	}
}

// TestNoneDownloadLocationOutranksRecoveredRepository pins the precedence: a
// package can record a source repository and still declare it is not
// downloadable, and the explicit NONE must not be replaced by the repository.
func TestNoneDownloadLocationOutranksRecoveredRepository(t *testing.T) {
	const in = `{
      "spdxVersion": "SPDX-2.3",
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "doc",
      "documentNamespace": "https://example.com/doc",
      "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: t"]},
      "packages": [{
        "name": "a", "SPDXID": "SPDXRef-a", "versionInfo": "1.0.0",
        "downloadLocation": "NONE", "filesAnalyzed": false,
        "sourceInfo": "Source repository: git+https://github.com/org/repo@deadbeef"
      }]
    }`

	out := ingestAndReexport(t, []byte(in), TargetSPDX23JSON)
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range doc.Packages {
		if p == nil || p.PackageName != "a" {
			continue
		}
		if p.PackageDownloadLocation != "NONE" {
			t.Fatalf("downloadLocation = %q, want the explicit NONE preserved", p.PackageDownloadLocation)
		}
		return
	}
	t.Fatal("component missing from output")
}

// TestDuplicatePURLVulnerabilitiesAndLicensesAreUnioned closes the last two
// set-valued fields at the graph level.
// Only licenses are exercised here. Vulnerabilities are not carried by
// ToGraph, so they cannot survive this path whatever the merge does;
// TestMergeComponentAssertionsUnionsEverySet covers them at the helper level
// instead of putting fixture data here that could never round-trip.
func TestDuplicatePURLLicensesAreUnioned(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{
				ID: "first", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0",
				Licenses: []License{{Value: "MIT", SPDXExpression: "MIT"}},
			},
			{
				ID: "second", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0",
				Licenses: []License{{Value: "Apache-2.0", SPDXExpression: "Apache-2.0"}},
			},
		},
		Dependencies: []Dependency{{Ref: "first", DependsOn: []string{"second"}}},
	}

	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	out, err := MarshalDepGraphJSON(graph, TargetCycloneDX17JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{"MIT", "Apache-2.0"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("license %q was discarded by the graph merge:\n%s", want, out)
		}
	}
}

// TestDuplicatePURLSupplierContactsAreUnioned exercises the graph-level merge
// for contacts specifically. Contacts are serialized as maps, so the string
// union used for supplier URLs would silently discard every one of them.
func TestDuplicatePURLSupplierContactsAreUnioned(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{
				ID: "first", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0",
				Supplier:         "Acme",
				SupplierContacts: []Contact{{Name: "First Contact", Email: "first@acme.example"}},
			},
			{
				ID: "second", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0",
				Supplier:         "Acme",
				SupplierContacts: []Contact{{Name: "Second Contact", Email: "second@acme.example"}},
			},
		},
		Dependencies: []Dependency{{Ref: "first", DependsOn: []string{"second"}}},
	}

	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	out, err := MarshalDepGraphJSON(graph, TargetCycloneDX17JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{"First Contact", "Second Contact"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("contact %q was discarded by the graph merge:\n%s", want, out)
		}
	}
}

// TestRenderedVCSRevisionIsValidatedOnEveryPath covers the paths that reach
// normalizeVCS without going through validatedVCSLocator: a CycloneDX vcs
// reference and an SPDX downloadLocation. An already-rendered "@<revision>"
// sits in the URL path, where url.Parse leaves it untouched, so it has to be
// split off and checked there too.
func TestRenderedVCSRevisionIsValidatedOnEveryPath(t *testing.T) {
	cdxIn := `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0", "type": "library", "name": "a", "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [{"type": "vcs", "url": "git+https://github.com/org/repo@ghp_abcd1234"}]
      }]
    }`

	spdxIn := `{
      "spdxVersion": "SPDX-2.3",
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "doc",
      "documentNamespace": "https://example.com/doc",
      "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: t"]},
      "packages": [{
        "name": "a", "SPDXID": "SPDXRef-a", "versionInfo": "1.0.0",
        "downloadLocation": "git+https://github.com/org/repo@ghp_abcd1234",
        "filesAnalyzed": false
      }]
    }`

	for name, in := range map[string]string{"cyclonedx-vcs-ref": cdxIn, "spdx-download-location": spdxIn} {
		for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
			out := string(ingestAndReexport(t, []byte(in), target))
			if strings.Contains(out, "ghp_abcd1234") {
				t.Fatalf("%s -> %s republished a token from a rendered revision:\n%s", name, target, out)
			}
			if !strings.Contains(out, "github.com/org/repo") {
				t.Fatalf("%s -> %s dropped the repository along with the token:\n%s", name, target, out)
			}
		}
	}
}

// TestMergeComponentAssertionsUnionsEverySet covers the merge helper directly,
// including vulnerabilities, which no ingest path currently carries — the
// union is part of the helper's contract even where an end-to-end fixture
// cannot reach it.
func TestMergeComponentAssertionsUnionsEverySet(t *testing.T) {
	dst := Component{
		Licenses:         []License{{Value: "MIT", SPDXExpression: "MIT"}},
		CPEs:             []string{"cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"},
		Digests:          []Digest{{Algorithm: "sha256", Value: strings.Repeat("a", 64)}},
		Vulnerabilities:  []Vulnerability{{ID: "CVE-2024-0001", Source: "osv"}},
		SupplierURLs:     []string{"https://first.example"},
		SupplierContacts: []Contact{{Name: "First"}},
		ExternalRefs:     []ExternalRef{{Type: "website", URL: "https://site.example"}},
	}
	src := Component{
		Licenses:         []License{{Value: "Apache-2.0", SPDXExpression: "Apache-2.0"}},
		CPEs:             []string{"cpe:2.3:a:v:p:2.0:*:*:*:*:*:*:*"},
		Digests:          []Digest{{Algorithm: "sha256", Value: strings.Repeat("b", 64)}},
		Vulnerabilities:  []Vulnerability{{ID: "CVE-2024-0002", Source: "osv"}},
		SupplierURLs:     []string{"https://second.example"},
		SupplierContacts: []Contact{{Name: "Second"}},
		ExternalRefs:     []ExternalRef{{Type: "documentation", URL: "https://docs.example"}},
	}

	mergeComponentAssertions(&dst, src)

	for name, got := range map[string]int{
		"licenses":        len(dst.Licenses),
		"cpes":            len(dst.CPEs),
		"digests":         len(dst.Digests),
		"vulnerabilities": len(dst.Vulnerabilities),
		"supplier urls":   len(dst.SupplierURLs),
		"contacts":        len(dst.SupplierContacts),
		"external refs":   len(dst.ExternalRefs),
	} {
		if got != 2 {
			t.Fatalf("%s: got %d entries after merge, want both retained", name, got)
		}
	}

	// Merging the same values again must not duplicate them.
	mergeComponentAssertions(&dst, src)
	if len(dst.Vulnerabilities) != 2 || len(dst.ExternalRefs) != 2 || len(dst.SupplierContacts) != 2 {
		t.Fatalf("re-merging duplicated entries: %+v", dst)
	}
}

// TestBareTokenQueryIsRejected covers a query with no "=": url.ParseQuery
// turns "?ghp_abcd1234" into a nameless key, so the credential-shape check has
// to run on parameter names as well as values.
func TestBareTokenQueryIsRejected(t *testing.T) {
	for _, raw := range []string{
		"https://repo.example/download?ghp_abcd1234",
		"https://repo.example/download?glpat-Abc123",
	} {
		if got := classifyAssertedDownloadLocation(raw); got.Kind != LocatorNone {
			t.Fatalf("classifyAssertedDownloadLocation(%q) = %+v, want it rejected", raw, got)
		}
		if isPublishableReferenceURL(raw) {
			t.Fatalf("isPublishableReferenceURL(%q) = true, want it rejected", raw)
		}
	}
	// A genuinely benign nameless query is still fine.
	if got := classifyAssertedDownloadLocation("https://repo.example/download?raw"); got.Kind == LocatorNone {
		t.Fatal("a benign nameless query was rejected")
	}
}

// TestMailtoTargetIsValidated covers the opaque body of a mailto reference,
// which none of the userinfo, query, or revision gates inspect.
func TestMailtoTargetIsValidated(t *testing.T) {
	valid := []string{"mailto:security@example.com", "mailto:first.last+tag@sub.example.org"}
	for _, value := range valid {
		if !isPublishableReferenceURL(value) {
			t.Fatalf("isPublishableReferenceURL(%q) = false, want a real address accepted", value)
		}
	}
	invalid := []string{
		"mailto:ghp_abcd1234", "mailto:notanaddress", "mailto:", "mailto:@example.com",
		"mailto:user@", "mailto:user@nodot",
	}
	for _, value := range invalid {
		if isPublishableReferenceURL(value) {
			t.Fatalf("isPublishableReferenceURL(%q) = true, want it rejected", value)
		}
	}
}

// TestNonGitVCSReferencesSurvive covers the other version-control tools. The
// "git+" trim did not apply to them, so their scheme was rejected outright.
func TestNonGitVCSReferencesSurvive(t *testing.T) {
	for _, locator := range []string{
		"svn+https://svn.example.org/project",
		"hg+https://hg.example.org/project",
		"bzr+https://bzr.example.org/project",
	} {
		if got := validatedVCSLocator(locator); got == "" {
			t.Fatalf("validatedVCSLocator(%q) = \"\", want the repository preserved", locator)
		}
	}
	// The safety gate still applies to them.
	if got := validatedVCSLocator("svn+https://tok:s3cret@svn.example.org/p"); got != "" {
		t.Fatalf("credential-bearing svn locator accepted: %q", got)
	}
}

// TestNamelessSupplierEntitySurvives covers a CycloneDX organizational entity
// that identifies itself only by URL or contact. The name is optional there,
// so gating the whole entity on it discarded compliance-relevant assertions.
func TestNamelessSupplierEntitySurvives(t *testing.T) {
	const in = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0", "type": "library", "name": "a", "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "supplier": {
          "url": ["https://supplier.example.com"],
          "contact": [{"name": "Security Team", "email": "security@supplier.example.com"}]
        }
      }]
    }`

	out := string(ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON))
	for _, want := range []string{"https://supplier.example.com", "Security Team", "security@supplier.example.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("nameless supplier lost %q:\n%s", want, out)
		}
	}
}

// TestURIBoundCPEUsesItsOwnGrammar covers CPE 2.2, whose components may be
// empty and whose edition field packs five values with "~" separators.
// Applying the 2.3 formatted-string rules rejected genuine identifiers.
func TestURIBoundCPEUsesItsOwnGrammar(t *testing.T) {
	valid := []string{
		"cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~",
		"cpe:/a:apache:log4j:2.14.1",
		"cpe:/o:linux:linux_kernel",
		"cpe:/a:vendor:product::update",
	}
	for _, value := range valid {
		if !isValidCPE(value) {
			t.Fatalf("isValidCPE(%q) = false, want a valid URI-bound CPE accepted", value)
		}
	}
	for _, value := range []string{"cpe:/a:vendor with space:product", "cpe:/z:vendor:product"} {
		if isValidCPE(value) {
			t.Fatalf("isValidCPE(%q) = true, want it rejected", value)
		}
	}
}

// TestEscapedControlInCPEIsRejected covers the escape branch, which skipped
// the printable-ASCII check for whatever followed a backslash.
func TestEscapedControlInCPEIsRejected(t *testing.T) {
	for _, value := range []string{
		"cpe:2.3:a:vendor:pro\\\x00duct:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor:pro\\ duct:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor:pro\\é:1.0:*:*:*:*:*:*:*",
	} {
		if isValidCPE(value) {
			t.Fatalf("isValidCPE(%q) = true, want an escaped non-printable rejected", value)
		}
	}
	// A legitimately escaped delimiter still works.
	if !isValidCPE(`cpe:2.3:a:ven\:dor:product:1.0:*:*:*:*:*:*:*`) {
		t.Fatal("a legitimately escaped colon was rejected")
	}
}

// TestClassifiedLocatorHashesSurvive covers integrity assertions attached to a
// distribution or vcs reference. Those land in scalar locator fields, so they
// bypassed the path where reference digests were preserved.
func TestClassifiedLocatorHashesSurvive(t *testing.T) {
	hash := strings.Repeat("f", 64)
	in := `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "bom-ref": "pkg:npm/a@1.0.0", "type": "library", "name": "a", "version": "1.0.0",
        "purl": "pkg:npm/a@1.0.0",
        "externalReferences": [
          {"type": "distribution", "url": "https://reg.example/a-1.0.0.tgz",
           "hashes": [{"alg": "SHA-256", "content": "` + hash + `"}]}
        ]
      }]
    }`

	raw := ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON)
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	comp := (*bom.Components)[0]
	if comp.ExternalReferences == nil {
		t.Fatalf("no external references:\n%s", raw)
	}
	for _, ref := range *comp.ExternalReferences {
		if ref.Type != cdx.ERTypeDistribution {
			continue
		}
		if ref.Hashes == nil || len(*ref.Hashes) != 1 {
			t.Fatalf("distribution reference lost its integrity assertion: %+v", ref)
		}
		if h := (*ref.Hashes)[0]; h.Algorithm != cdx.HashAlgoSHA256 || h.Value != hash {
			t.Fatalf("distribution hash = %+v, want SHA-256 with the asserted value", h)
		}
		return
	}
	t.Fatalf("distribution reference missing:\n%s", raw)
}

// TestRegistryRootSurvivesBomlyRoundTrip is the regression test for the
// sharpest failure this classifier exists to prevent, reached through Bomly's
// own output: a registry root republished as an exact download location.
//
// CycloneDX defines `distribution` as where the artifact can be obtained, so
// an unmarked reference is promoted on ingest. Bomly marks its own
// registry-root references, and that marker has to be believed over the URL's
// path shape.
func TestRegistryRootSurvivesBomlyRoundTrip(t *testing.T) {
	in := `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [
        {"bom-ref": "pkg:gem/a@1.0.0", "type": "library", "name": "a", "version": "1.0.0",
         "purl": "pkg:gem/a@1.0.0",
         "externalReferences": [
           {"type": "distribution", "url": "https://rubygems.org/", "comment": "` + registryRootMarker + `"}]},
        {"bom-ref": "pkg:npm/b@1.0.0", "type": "library", "name": "b", "version": "1.0.0",
         "purl": "pkg:npm/b@1.0.0",
         "externalReferences": [
           {"type": "distribution", "url": "https://registry.npmjs.org/b/-/b-1.0.0.tgz"}]}
      ]
    }`

	out := ingestAndReexport(t, []byte(in), TargetSPDX23JSON)
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range doc.Packages {
		if p == nil {
			continue
		}
		switch p.PackageName {
		case "a":
			if p.PackageDownloadLocation != "NOASSERTION" {
				t.Fatalf("a marked registry root became a download location: %q", p.PackageDownloadLocation)
			}
		case "b":
			if p.PackageDownloadLocation != "https://registry.npmjs.org/b/-/b-1.0.0.tgz" {
				t.Fatalf("an unmarked exact artifact was not promoted: %q", p.PackageDownloadLocation)
			}
		}
	}
}

// TestLocatorSlotsMergeAtomically covers the merge of two copies of one
// component that each assert a different distribution URL with its own hash.
// Merging URL, comment, and digests independently would attach one URL's hash
// to the other — a false integrity assertion.
func TestLocatorSlotsMergeAtomically(t *testing.T) {
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)

	dst := Component{
		ArtifactURL:     "https://primary.example/a-1.0.0.tgz",
		ArtifactDigests: []Digest{{Algorithm: "sha256", Value: first}},
	}
	src := Component{
		ArtifactURL:     "https://mirror.example/a-1.0.0.tgz",
		ArtifactComment: "mirror",
		ArtifactDigests: []Digest{{Algorithm: "sha256", Value: second}},
	}

	mergeComponentAssertions(&dst, src)

	if len(dst.ArtifactDigests) != 1 || dst.ArtifactDigests[0].Value != first {
		t.Fatalf("the surviving URL picked up the other URL's hashes: %+v", dst.ArtifactDigests)
	}
	if dst.ArtifactComment != "" {
		t.Fatalf("the surviving URL picked up the other URL's comment: %q", dst.ArtifactComment)
	}
	// The losing locator is preserved rather than dropped.
	var kept *ExternalRef
	for i := range dst.ExternalRefs {
		if dst.ExternalRefs[i].URL == "https://mirror.example/a-1.0.0.tgz" {
			kept = &dst.ExternalRefs[i]
		}
	}
	if kept == nil {
		t.Fatalf("the losing locator was discarded: %+v", dst.ExternalRefs)
	}
	if kept.Comment != "mirror" || len(kept.Digests) != 1 || kept.Digests[0].Value != second {
		t.Fatalf("the preserved locator lost its own assertions: %+v", kept)
	}
}

// TestURIBoundCPEPercentEscapes covers the URI binding's encoding rules.
func TestURIBoundCPEPercentEscapes(t *testing.T) {
	if !isValidCPE("cpe:/a:vendor%3Aname:product") {
		t.Fatal("a valid percent escape was rejected")
	}
	for _, value := range []string{"cpe:/a:vendor%ZZ:product", "cpe:/a:vendor%:product", "cpe:/a:vendor%4:product"} {
		if isValidCPE(value) {
			t.Fatalf("isValidCPE(%q) = true, want a malformed percent escape rejected", value)
		}
	}
}

// TestNonGitSourceInfoRoundTrips covers the SPDX recovery branch, which only
// recognized "git+" while the writer can emit any tool prefix.
func TestNonGitSourceInfoRoundTrips(t *testing.T) {
	repo, vcs := parseSPDXSourceInfo("Source repository: svn+https://svn.example.org/project")
	if vcs != "svn+https://svn.example.org/project" || repo != "" {
		t.Fatalf("parseSPDXSourceInfo dropped a non-Git locator: repo=%q vcs=%q", repo, vcs)
	}
}

// TestIngestedVCSOutranksScorecardInSourceInfo pins the precedence when an
// artifact owns the download location and both sources name a repository.
func TestIngestedVCSOutranksScorecardInSourceInfo(t *testing.T) {
	got := spdxSourceInfo(Component{
		ArtifactURL: "https://reg.example/a-1.0.0.tgz",
		VCSURL:      "git+https://github.com/ingested/repo",
		Repository:  "https://github.com/scorecard/repo",
	})
	if !strings.Contains(got, "ingested/repo") {
		t.Fatalf("sourceInfo = %q, want the ingested assertion to outrank the matcher", got)
	}
}

// TestCredentialInPathIsRejected covers a token sitting in the URL path.
// looksLikeCredential was applied to query names and values, revisions, mail
// addresses, and URN segments, but never to path segments — where a value has
// no userinfo, no query, and no fragment, so every other gate passes it.
func TestCredentialInPathIsRejected(t *testing.T) {
	tokenPaths := []string{
		"https://repo.example/download/ghp_abcd1234/pkg.tgz",
		"https://repo.example/glpat-Abc123/pkg.tgz",
		"https://repo.example/download/%67hp_abcd1234/pkg.tgz",
	}
	for _, raw := range tokenPaths {
		if got := classifyResolvedURL(raw, "", ""); got.Kind != LocatorNone {
			t.Fatalf("classifyResolvedURL(%q) = %+v, want it rejected", raw, got)
		}
		if got := classifyAssertedDownloadLocation(raw); got.Kind != LocatorNone {
			t.Fatalf("classifyAssertedDownloadLocation(%q) = %+v, want it rejected", raw, got)
		}
		if isPublishableReferenceURL(raw) {
			t.Fatalf("isPublishableReferenceURL(%q) = true, want it rejected", raw)
		}
	}
	// An ordinary package path is unaffected.
	if got := classifyResolvedURL("https://registry.npmjs.org/a/-/a-1.0.0.tgz", "", ""); got.Kind == LocatorNone {
		t.Fatal("an ordinary package path was rejected")
	}
}

// TestNonGitVCSDownloadLocationRoundTrips covers an SPDX downloadLocation that
// uses a non-Git tool prefix. The shared classifier recognized only "git+", so
// the remaining compound scheme failed the transport gate.
func TestNonGitVCSDownloadLocationRoundTrips(t *testing.T) {
	for _, locator := range []string{
		"svn+https://svn.example.org/project",
		"hg+https://hg.example.org/project",
	} {
		in := `{
          "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "doc",
          "documentNamespace": "https://example.com/doc",
          "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: t"]},
          "packages": [{"name": "a", "SPDXID": "SPDXRef-a", "versionInfo": "1.0.0",
            "downloadLocation": "` + locator + `", "filesAnalyzed": false}]
        }`
		out := string(ingestAndReexport(t, []byte(in), TargetSPDX23JSON))
		if !strings.Contains(out, "example.org/project") {
			t.Fatalf("%s was dropped on re-export:\n%s", locator, out)
		}
	}
}

// TestSPDXSentinelsAreCaseSensitive covers ordinary free text that happens to
// spell a reserved marker in mixed case.
func TestSPDXSentinelsAreCaseSensitive(t *testing.T) {
	for _, value := range []string{"None", "NoAssertion", "none"} {
		if got := parseSPDXEntity(value); got != value {
			t.Fatalf("parseSPDXEntity(%q) = %q, want the free text preserved", value, got)
		}
	}
	for _, value := range []string{"NONE", "NOASSERTION", ""} {
		if got := parseSPDXEntity(value); got != "" {
			t.Fatalf("parseSPDXEntity(%q) = %q, want the sentinel treated as absent", value, got)
		}
	}
}

// TestRegistryRootReferenceKeepsItsHashes covers the encoder branch that
// recreated a marked registry-root reference without its integrity assertion.
func TestRegistryRootReferenceKeepsItsHashes(t *testing.T) {
	hash := strings.Repeat("e", 64)
	in := `{
      "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
      "components": [{
        "bom-ref": "pkg:gem/a@1.0.0", "type": "library", "name": "a", "version": "1.0.0",
        "purl": "pkg:gem/a@1.0.0",
        "externalReferences": [{
          "type": "distribution", "url": "https://rubygems.org/",
          "comment": "` + registryRootMarker + `",
          "hashes": [{"alg": "SHA-256", "content": "` + hash + `"}]}]
      }]
    }`

	raw := ingestAndReexport(t, []byte(in), TargetCycloneDX17JSON)
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, ref := range *(*bom.Components)[0].ExternalReferences {
		if ref.URL != "https://rubygems.org/" {
			continue
		}
		if ref.Hashes == nil || len(*ref.Hashes) != 1 {
			t.Fatalf("registry-root reference lost its hashes: %+v", ref)
		}
		if h := (*ref.Hashes)[0]; h.Algorithm != cdx.HashAlgoSHA256 || h.Value != hash {
			t.Fatalf("registry-root hash = %+v, want SHA-256 with the asserted value", h)
		}
		return
	}
	t.Fatalf("registry-root reference missing:\n%s", raw)
}

// TestGraphLocatorMergeMirrorsModel covers the graph layer, which had the same
// three merge defects the model layer did: a conflicting locator discarded, a
// matching locator's digests dropped, and a duplicate external reference
// skipped instead of merged.
func TestGraphLocatorMergeMirrorsModel(t *testing.T) {
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)

	doc := &Document{
		Components: []Component{
			{
				ID: "first", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0",
				ArtifactURL:     "https://primary.example/a-1.0.0.tgz",
				ArtifactDigests: []Digest{{Algorithm: "sha256", Value: first}},
				ExternalRefs:    []ExternalRef{{Type: "documentation", URL: "https://docs.example"}},
			},
			{
				ID: "second", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0",
				ArtifactURL:     "https://mirror.example/a-1.0.0.tgz",
				ArtifactDigests: []Digest{{Algorithm: "sha256", Value: second}},
				ExternalRefs: []ExternalRef{{
					Type: "documentation", URL: "https://docs.example", Comment: "from the second copy",
				}},
			},
		},
		Dependencies: []Dependency{{Ref: "first", DependsOn: []string{"second"}}},
	}

	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	out, err := MarshalDepGraphJSON(graph, TargetCycloneDX17JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rendered := string(out)
	for name, want := range map[string]string{
		"primary URL":         "https://primary.example/a-1.0.0.tgz",
		"mirror URL":          "https://mirror.example/a-1.0.0.tgz",
		"primary hash":        first,
		"duplicate's comment": "from the second copy",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("%s was discarded by the graph merge:\n%s", name, rendered)
		}
	}
}
