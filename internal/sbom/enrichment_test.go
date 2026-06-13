package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-cli/sdk"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// enrichedGraphAndRegistry builds a one-node graph plus a registry entry, keyed
// by the same PURL, carrying matching-stage enrichment (licenses, CPE, digest,
// vulnerability, EOL).
func enrichedGraphAndRegistry(t *testing.T) (*sdk.Graph, *sdk.PackageRegistry) {
	t.Helper()
	const purl = "pkg:npm/react@18.2.0"

	g := sdk.New()
	react := sdk.NewDependencyWithID("react@18.2.0", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "react",
		Version:   "18.2.0",
		PURL:      purl,
		Ecosystem: "npm"},
	})
	if err := g.AddNode(react); err != nil {
		t.Fatalf("add node: %v", err)
	}

	registry := sdk.NewPackageRegistry()
	pkg := registry.Ensure(purl)
	pkg.Name = "react"
	pkg.Version = "18.2.0"
	pkg.Matched = true
	pkg.Licenses = []sdk.PackageLicense{{SPDXExpression: "MIT"}}
	pkg.CPEs = []string{"cpe:2.3:a:facebook:react:18.2.0:*:*:*:*:*:*:*"}
	pkg.Digests = []sdk.Digest{{Algorithm: "sha256", Value: "abc123"}}
	pkg.EOL = &sdk.PackageEOL{EOL: true, EOLDate: "2025-01-01", Cycle: "18"}
	pkg.Vulnerabilities = []sdk.Vulnerability{{
		ID:             "CVE-2024-0001",
		Source:         "osv",
		ParsedSeverity: "high",
		Details:        "prototype pollution",
		CVSS:           []sdk.CVSSScore{{Score: 7.5, Vector: "CVSS:3.1/AV:N", Version: "3.1"}},
		CWEs:           []sdk.CWE{{ID: "CWE-1321"}},
		FixedVersions:  []string{"18.3.0"},
		References:     []sdk.Reference{{URL: "https://example.com/advisory"}},
	}}
	return g, registry
}

func TestFromDepGraphEnrichesCycloneDXFromRegistry(t *testing.T) {
	g, registry := enrichedGraphAndRegistry(t)
	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{Registry: registry}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}

	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		t.Fatalf("decode cyclonedx: %v", err)
	}

	if bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatal("expected components")
	}
	comp := (*bom.Components)[0]
	if comp.CPE == "" {
		t.Fatal("expected component CPE from registry")
	}
	if comp.Hashes == nil || len(*comp.Hashes) != 1 || (*comp.Hashes)[0].Algorithm != cdx.HashAlgoSHA256 {
		t.Fatalf("expected SHA-256 hash, got %#v", comp.Hashes)
	}
	if comp.Properties == nil {
		t.Fatal("expected EOL properties")
	}
	foundEOL := false
	for _, p := range *comp.Properties {
		if p.Name == "bomly:eol" && p.Value == "true" {
			foundEOL = true
		}
	}
	if !foundEOL {
		t.Fatalf("expected bomly:eol=true property, got %#v", comp.Properties)
	}

	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %#v", bom.Vulnerabilities)
	}
	vuln := (*bom.Vulnerabilities)[0]
	if vuln.ID != "CVE-2024-0001" {
		t.Fatalf("unexpected vuln id %q", vuln.ID)
	}
	if vuln.Ratings == nil || len(*vuln.Ratings) != 1 {
		t.Fatalf("expected 1 rating, got %#v", vuln.Ratings)
	}
	rating := (*vuln.Ratings)[0]
	if rating.Severity != cdx.SeverityHigh || rating.Method != cdx.ScoringMethodCVSSv31 {
		t.Fatalf("unexpected rating %#v", rating)
	}
	if rating.Score == nil || *rating.Score != 7.5 {
		t.Fatalf("unexpected score %#v", rating.Score)
	}
	if vuln.CWEs == nil || len(*vuln.CWEs) != 1 || (*vuln.CWEs)[0] != 1321 {
		t.Fatalf("expected CWE 1321, got %#v", vuln.CWEs)
	}
	if vuln.Affects == nil || len(*vuln.Affects) != 1 || (*vuln.Affects)[0].Ref != "react@18.2.0" {
		t.Fatalf("expected affects ref react@18.2.0, got %#v", vuln.Affects)
	}
}

func TestFromDepGraphEnrichesSPDXFromRegistry(t *testing.T) {
	g, registry := enrichedGraphAndRegistry(t)
	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{Registry: registry}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(doc.Packages))
	}
	pkg := doc.Packages[0]
	if pkg.PackageLicenseConcluded != "MIT" {
		t.Fatalf("expected MIT license, got %q", pkg.PackageLicenseConcluded)
	}
	if len(pkg.PackageChecksums) != 1 || string(pkg.PackageChecksums[0].Algorithm) != "SHA256" {
		t.Fatalf("expected SHA256 checksum, got %#v", pkg.PackageChecksums)
	}
	var cpeRef, advisoryRef bool
	for _, ref := range pkg.PackageExternalReferences {
		if ref == nil {
			continue
		}
		switch {
		case ref.Category == "SECURITY" && ref.RefType == "cpe23Type":
			cpeRef = true
		case ref.Category == "SECURITY" && ref.RefType == "advisory" && strings.Contains(ref.Locator, "advisory"):
			advisoryRef = true
		}
	}
	if !cpeRef {
		t.Fatalf("expected SECURITY cpe23Type external ref, got %#v", pkg.PackageExternalReferences)
	}
	if !advisoryRef {
		t.Fatalf("expected SECURITY advisory external ref, got %#v", pkg.PackageExternalReferences)
	}
	if !strings.Contains(pkg.PackageComment, "eol=true") {
		t.Fatalf("expected eol annotation in package comment, got %q", pkg.PackageComment)
	}
}
