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

// TestIngestedCoordinateOrg covers both ways a producer splits a namespaced
// package. Bomly writes the whole ecosystem-native name and repeats the
// namespace in `group`; most other producers write a bare name plus `group`.
// Coordinates joins Org with Name, so the split decides whether Org may be set:
// setting it on an already-qualified name doubles the namespace, and leaving it
// unset on a bare name loses it.
func TestIngestedCoordinateOrg(t *testing.T) {
	tests := []struct {
		name      string
		component Component
		want      string
	}{
		{
			name:      "bomly's own qualified npm name keeps Org empty",
			component: Component{Name: "@scope/pkg", Org: "@scope", PURL: "pkg:npm/@scope/pkg@1.0.0"},
			want:      "",
		},
		{
			name:      "bomly's own qualified go name keeps Org empty",
			component: Component{Name: "github.com/google/uuid", Org: "github.com/google", PURL: "pkg:golang/github.com/google/uuid@v1.6.0"},
			want:      "",
		},
		{
			name:      "bomly's own qualified maven name keeps Org empty",
			component: Component{Name: "org.apache.commons:commons-lang3", Org: "org.apache.commons", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.14.0"},
			want:      "",
		},
		{
			name:      "third-party bare npm name takes the namespace",
			component: Component{Name: "pkg", Org: "@scope", PURL: "pkg:npm/@scope/pkg@1.0.0"},
			want:      "@scope",
		},
		{
			name:      "third-party bare go name takes the namespace",
			component: Component{Name: "uuid", Org: "github.com/google", PURL: "pkg:golang/github.com/google/uuid@v1.6.0"},
			want:      "github.com/google",
		},
		{
			name:      "third-party bare maven name takes the namespace",
			component: Component{Name: "commons-lang3", Org: "org.apache.commons", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.14.0"},
			want:      "org.apache.commons",
		},
		{
			// The PURL is structured and export derives `group` from it, so it
			// wins where the two disagree.
			name:      "purl namespace outranks a differing group",
			component: Component{Name: "pkg", Org: "scope", PURL: "pkg:npm/@scope/pkg@1.0.0"},
			want:      "@scope",
		},
		{
			name:      "group survives when the purl has no namespace",
			component: Component{Name: "widget", Org: "acme", PURL: "pkg:generic/widget@1.0.0"},
			want:      "acme",
		},
		{
			// PURL normalization lowercases the Go namespace while the name
			// keeps its original case. A case-sensitive prefix test misses
			// this and doubles the namespace.
			name:      "case-normalized purl namespace still matches the name",
			component: Component{Name: "github.com/BurntSushi/toml", Org: "github.com/burntsushi", PURL: "pkg:golang/github.com/burntsushi/toml@v1.4.0"},
			want:      "",
		},
		{
			name:      "case-normalized namespace on a nested module path",
			component: Component{Name: "github.com/Masterminds/semver/v3", Org: "github.com/masterminds/semver", PURL: "pkg:golang/github.com/masterminds/semver/v3@v3.3.0"},
			want:      "",
		},
		{
			name:      "no namespace anywhere",
			component: Component{Name: "requests", PURL: "pkg:pypi/requests@2.31.0"},
			want:      "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ingestedCoordinateOrg(tc.component); got != tc.want {
				t.Fatalf("expected Org %q, got %q", tc.want, got)
			}
		})
	}
}

// TestIngestBareNameRecoversQualifiedName covers a document written the way
// most producers write one -- `group` plus a bare `name` -- reaching the graph
// with its namespaced name intact, and keeping its group on re-export.
func TestIngestBareNameRecoversQualifiedName(t *testing.T) {
	tests := []struct {
		name      string
		component Component
		ecosystem string
		wantName  string
		wantGroup string
	}{
		{
			name:      "npm scope",
			component: Component{ID: "pkg-1", Name: "pkg", Org: "@scope", Version: "1.0.0", PURL: "pkg:npm/@scope/pkg@1.0.0"},
			ecosystem: "npm",
			wantName:  "@scope/pkg",
			wantGroup: "@scope",
		},
		{
			name:      "go module",
			component: Component{ID: "uuid-1", Name: "uuid", Org: "github.com/google", Version: "v1.6.0", PURL: "pkg:golang/github.com/google/uuid@v1.6.0"},
			ecosystem: "go",
			wantName:  "github.com/google/uuid",
			wantGroup: "github.com/google",
		},
		{
			// Generic packages do not join Org into the display name, but the
			// group must still survive the round trip.
			name:      "generic package keeps its group",
			component: Component{ID: "widget-1", Name: "widget", Org: "acme", Version: "1.0.0", PURL: "pkg:generic/widget@1.0.0"},
			ecosystem: "generic",
			wantName:  "widget",
			wantGroup: "acme",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			component := tc.component
			component.Ecosystem = tc.ecosystem
			doc := &Document{
				Name:         "ingested",
				Components:   []Component{component},
				Dependencies: []Dependency{{Ref: component.ID}},
				Roots:        []string{component.ID},
			}

			graph, err := ToGraph(doc)
			if err != nil {
				t.Fatalf("to graph: %v", err)
			}
			found := false
			graph.WalkNodes(func(pkg *sdk.Dependency) bool {
				found = true
				if got := pkg.EcosystemName(); got != tc.wantName {
					t.Fatalf("expected name %q, got %q", tc.wantName, got)
				}
				return true
			})
			if !found {
				t.Fatal("expected a node in the ingested graph")
			}

			out, err := MarshalDepGraphJSON(graph, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
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
			if got := (*bom.Components)[0].Group; got != tc.wantGroup {
				t.Fatalf("expected group %q on re-export, got %q", tc.wantGroup, got)
			}
		})
	}
}

// TestCycloneDXGroupSurvivesRoundTrip covers reading `group` back into the
// document model, and — the part that matters — that ingesting a document does
// not corrupt package names.
//
// A component's name is already ecosystem-native ("@scope/pkg"), while SDK
// coordinates join Org with Name to build that same string. Carrying the group
// into Coordinates.Org made the join happen twice ("@scope/@scope/pkg"), so
// this asserts the name a re-ingested package reports, not just the field.
func TestCycloneDXGroupSurvivesRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		pkgName   string
		purl      string
		ecosystem string
		wantGroup string
	}{
		{
			name:      "npm scope",
			pkgName:   "@scope/pkg",
			purl:      "pkg:npm/@scope/pkg@1.0.0",
			ecosystem: "npm",
			wantGroup: "@scope",
		},
		{
			name:      "go module",
			pkgName:   "github.com/google/uuid",
			purl:      "pkg:golang/github.com/google/uuid@v1.6.0",
			ecosystem: "go",
			wantGroup: "github.com/google",
		},
		{
			name:      "maven coordinates",
			pkgName:   "org.apache.commons:commons-lang3",
			purl:      "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
			ecosystem: "maven",
			wantGroup: "org.apache.commons",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := sdk.New()
			dep := sdk.NewDependencyWithID(tc.pkgName+"@1.0.0", sdk.Dependency{Coordinates: sdk.Coordinates{
				Name:      tc.pkgName,
				Version:   "1.0.0",
				PURL:      tc.purl,
				Ecosystem: sdk.Ecosystem(tc.ecosystem),
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
			if doc.Components[0].Org != tc.wantGroup {
				t.Fatalf("expected Org %q, got %q", tc.wantGroup, doc.Components[0].Org)
			}

			graph, err := ToGraph(doc)
			if err != nil {
				t.Fatalf("to graph: %v", err)
			}
			found := false
			graph.WalkNodes(func(pkg *sdk.Dependency) bool {
				found = true
				if got := pkg.EcosystemName(); got != tc.pkgName {
					t.Fatalf("re-ingested name changed: expected %q, got %q", tc.pkgName, got)
				}
				return true
			})
			if !found {
				t.Fatal("expected a node in the re-ingested graph")
			}

			// Re-exporting recovers the group from the PURL, so the namespace
			// survives the full round trip without living on the coordinates.
			out2, err := MarshalDepGraphJSON(graph, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
			if err != nil {
				t.Fatalf("re-marshal cyclonedx: %v", err)
			}
			doc2, _, err := UnmarshalAutoJSON(out2)
			if err != nil {
				t.Fatalf("re-unmarshal document: %v", err)
			}
			if len(doc2.Components) != 1 || doc2.Components[0].Org != tc.wantGroup {
				t.Fatalf("group lost on re-export: %#v", doc2.Components)
			}
		})
	}
}
