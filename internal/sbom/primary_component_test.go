package sbom

import (
	"bytes"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
)

// TestCycloneDXPrimaryComponentCarriesFullDetail covers a natural single-root
// graph, where the root is both the document's subject and an inventory entry.
// The primary component used to be a reduced copy, describing the scanned
// project with less than the inventory knew about the very same package.
func TestCycloneDXPrimaryComponentCarriesFullDetail(t *testing.T) {
	g, registry := enrichedGraphAndRegistry(t)
	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{Registry: registry}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}

	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		t.Fatalf("decode cyclonedx: %v", err)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("expected metadata.component")
	}
	primary := bom.Metadata.Component

	if primary.Licenses == nil || len(*primary.Licenses) == 0 {
		t.Fatalf("expected licenses on the primary component, got %#v", primary.Licenses)
	}
	if (*primary.Licenses)[0].License == nil || (*primary.Licenses)[0].License.ID != "MIT" {
		t.Fatalf("expected MIT license id, got %#v", (*primary.Licenses)[0])
	}
	if primary.CPE == "" {
		t.Fatal("expected CPE on the primary component")
	}
	if primary.Hashes == nil || len(*primary.Hashes) == 0 {
		t.Fatalf("expected hashes on the primary component, got %#v", primary.Hashes)
	}
	if primary.Properties == nil {
		t.Fatal("expected EOL properties on the primary component")
	}
	foundEOL := false
	for _, p := range *primary.Properties {
		if p.Name == "bomly:eol" && p.Value == "true" {
			foundEOL = true
		}
	}
	if !foundEOL {
		t.Fatalf("expected bomly:eol property on the primary component, got %#v", primary.Properties)
	}

	// The inventory twin and the primary describe one package identically.
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("expected 1 inventory component, got %#v", bom.Components)
	}
	twin := (*bom.Components)[0]
	if twin.BOMRef != primary.BOMRef {
		t.Fatalf("expected the same package, got %q and %q", twin.BOMRef, primary.BOMRef)
	}
	if twin.CPE != primary.CPE || twin.PackageURL != primary.PackageURL {
		t.Fatalf("primary and inventory disagree: %+v vs %+v", primary, twin)
	}
}

// TestCycloneDXPrimaryComponentKeepsSecurityReferencesLast pins the ordering
// the provenance references rely on: a component's own origin references come
// first, and the document-level security references follow.
func TestCycloneDXPrimaryComponentKeepsSecurityReferencesLast(t *testing.T) {
	g := sdk.New()
	dep := sdk.NewDependencyWithID("left-pad@1.3.0", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Name:      "left-pad",
			Version:   "1.3.0",
			PURL:      "pkg:npm/left-pad@1.3.0",
			Ecosystem: "npm",
		},
		Origin: &sdk.DependencyOrigin{ArtifactURL: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add node: %v", err)
	}

	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{
		Provenance: Provenance{
			SecurityContact:            "security@example.com",
			VulnerabilityDisclosureURL: "https://example.com/security",
		},
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.ExternalReferences == nil {
		t.Fatal("expected external references on the primary component")
	}
	refs := *bom.Metadata.Component.ExternalReferences
	if len(refs) != 3 {
		t.Fatalf("expected the distribution reference plus 2 security references, got %#v", refs)
	}
	if refs[0].Type != cdx.ERTypeDistribution {
		t.Fatalf("expected the component's own reference first, got %#v", refs[0])
	}
	if refs[1].Type != cdx.ERTypeSecurityContact || refs[2].Type != cdx.ERTypeAdvisories {
		t.Fatalf("expected security references last, got %#v", refs[1:])
	}
}

// TestCycloneDXComponentGroup covers publishing the package namespace as
// CycloneDX `group`, taken from the PURL so the two always agree.
func TestCycloneDXComponentGroup(t *testing.T) {
	tests := []struct {
		name string
		purl string
		want string
	}{
		{name: "npm scope", purl: "pkg:npm/@scope/pkg@1.0.0", want: "@scope"},
		{name: "go module owner", purl: "pkg:golang/github.com/google/uuid@v1.6.0", want: "github.com/google"},
		{name: "maven group", purl: "pkg:maven/org.apache.commons/commons-lang3@3.14.0", want: "org.apache.commons"},
		{name: "namespaceless package", purl: "pkg:pypi/requests@2.31.0", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := sdk.New()
			dep := sdk.NewDependencyWithID("pkg@1", sdk.Dependency{Coordinates: sdk.Coordinates{
				Name:    "pkg",
				Version: "1",
				PURL:    tc.purl,
			}})
			if err := g.AddNode(dep); err != nil {
				t.Fatalf("add node: %v", err)
			}

			out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
			if err != nil {
				t.Fatalf("marshal cyclonedx: %v", err)
			}
			var bom cdx.BOM
			if err := json.Unmarshal(out, &bom); err != nil {
				t.Fatalf("unmarshal cyclonedx: %v", err)
			}
			if bom.Components == nil || len(*bom.Components) != 1 {
				t.Fatalf("expected 1 component, got %#v", bom.Components)
			}
			if got := (*bom.Components)[0].Group; got != tc.want {
				t.Fatalf("expected group %q, got %q", tc.want, got)
			}
		})
	}
}

// TestCycloneDXGroupSurvivesRoundTrip covers reading `group` back on ingest so
// a re-ingested document keeps the namespace it published.
func TestCycloneDXGroupSurvivesRoundTrip(t *testing.T) {
	g := sdk.New()
	dep := sdk.NewDependencyWithID("@scope/pkg@1.0.0", sdk.Dependency{Coordinates: sdk.Coordinates{
		Name:      "@scope/pkg",
		Version:   "1.0.0",
		PURL:      "pkg:npm/@scope/pkg@1.0.0",
		Ecosystem: "npm",
	}})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add node: %v", err)
	}

	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}

	doc, _, err := UnmarshalAutoJSON(out)
	if err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(doc.Components))
	}
	if doc.Components[0].Org != "@scope" {
		t.Fatalf("expected Org %q, got %q", "@scope", doc.Components[0].Org)
	}

	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	found := false
	graph.WalkNodes(func(pkg *sdk.Dependency) bool {
		found = true
		if pkg.Org != "@scope" {
			t.Fatalf("expected coordinates Org %q, got %q", "@scope", pkg.Org)
		}
		return true
	})
	if !found {
		t.Fatal("expected a node in the re-ingested graph")
	}
}
