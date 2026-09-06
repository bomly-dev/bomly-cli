package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
)

// scopedGraph builds a graph whose one dependency is reachable from both a
// runtime and a development root -- the shape whose scope set the export used
// to flatten (survey defect 2).
func scopedGraph(t *testing.T, scopes ...sdk.Scope) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	node, err := sdk.NewDependencyNode(sdk.Coordinates{Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("construct node: %v", err)
	}
	node.Scopes = scopes
	if err := g.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}
	return g
}

func componentScopes(t *testing.T, doc *Document, name string) []sdk.Scope {
	t.Helper()
	return componentNamed(t, doc, name).Scopes
}

// A multi-scope node keeps both scopes through an export and back, in both
// formats. Before this, export wrote the single merged precedence value and
// the union PR #406 established stopped at the SBOM boundary.
func TestScopeSetSurvivesTheExportBoundary(t *testing.T) {
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX16JSON} {
		t.Run(string(target), func(t *testing.T) {
			g := scopedGraph(t, sdk.ScopeRuntime, sdk.ScopeDevelopment)
			raw, err := MarshalDepGraphJSON(g, target, BuildOptions{}, EncodeOptions{Pretty: true})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			doc, _, err := UnmarshalAutoJSON(raw)
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			got := componentScopes(t, doc, "widget")
			if len(got) != 2 {
				t.Fatalf("scopes = %v, want both runtime and development\n%s", got, raw)
			}
			var runtime, development bool
			for _, scope := range got {
				runtime = runtime || scope == sdk.ScopeRuntime
				development = development || scope == sdk.ScopeDevelopment
			}
			if !runtime || !development {
				t.Errorf("scopes = %v, want both runtime and development", got)
			}
		})
	}
}

// The scalar each format holds is still written, so a consumer that reads only
// the native field gets a true statement. Runtime wins a mixed set, because a
// package reachable at runtime ships whatever else is true of it.
func TestCycloneDXStillWritesItsScalarScope(t *testing.T) {
	g := scopedGraph(t, sdk.ScopeDevelopment, sdk.ScopeRuntime)
	raw, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatalf("no components:\n%s", raw)
	}
	component := (*bom.Components)[0]
	if component.Scope != cdx.ScopeRequired {
		t.Errorf("scope = %q, want %q", component.Scope, cdx.ScopeRequired)
	}
	if component.Properties == nil {
		t.Fatalf("the scope set has no carrier:\n%s", raw)
	}
	var carrier string
	for _, property := range *component.Properties {
		if property.Name == sdk.CycloneDXScopeProperty {
			carrier = property.Value
		}
	}
	if carrier != "development,runtime" {
		t.Errorf("carrier = %q, want the sorted set", carrier)
	}
}

// A CycloneDX document Bomly did not write yields scopes from the SDK's
// vocabulary, not the raw CycloneDX token. Ingest used to copy "required"
// straight through, minting nodes scoped to a value no SDK filter matches
// (survey defect 1).
//
// The rows are the CycloneDX specification's own reading of its vocabulary,
// which ADR-0037's 2026-09-06 resolution settled and SDK v0.9.6 implements
// (bomly-dev/bomly-sdk#63). An "optional" component is one not installed or
// otherwise inaccessible by any means -- a component that is installed but
// merely unreachable must be spelled "required" -- so it is absent from what
// runs, which is development for Bomly's filtering. Only "required" reads as
// runtime.
//
// The "optional" row previously asserted runtime, pinning a deviation this
// repo had recorded as open. It is now the ADR's rule rather than a
// disagreement with it.
func TestForeignCycloneDXScopesMapIntoTheSDKVocabulary(t *testing.T) {
	for _, testCase := range []struct {
		native string
		want   sdk.Scope
	}{
		{"required", sdk.ScopeRuntime},
		{"optional", sdk.ScopeDevelopment},
		{"excluded", sdk.ScopeDevelopment},
	} {
		t.Run(testCase.native, func(t *testing.T) {
			raw := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {"bom-ref": "pkg:npm/widget@1.0.0", "type": "library", "name": "widget",
     "version": "1.0.0", "purl": "pkg:npm/widget@1.0.0", "scope": "` + testCase.native + `"}
  ]
}`
			doc, _, err := UnmarshalAutoJSON([]byte(raw))
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			got := componentScopes(t, doc, "widget")
			if len(got) != 1 || got[0] != testCase.want {
				t.Fatalf("scopes = %v, want [%s]", got, testCase.want)
			}
			// And the value reaches the graph as a scope the pipeline's own
			// filters recognize, which is the half that was actually broken.
			g, err := ToGraph(doc)
			if err != nil {
				t.Fatalf("to graph: %v", err)
			}
			nodes := g.DependencyNodes()
			if len(nodes) != 1 {
				t.Fatalf("nodes = %d", len(nodes))
			}
			for _, scope := range nodes[0].Scopes {
				if parsed, err := sdk.ParseScope(string(scope)); err != nil || parsed != scope {
					t.Errorf("node scope %q is outside the SDK vocabulary", scope)
				}
			}
		})
	}
}

// A carrier the SDK refuses is treated as absent, not as a reason to drop the
// component's scope altogether: the native scalar is still a true statement.
func TestMalformedScopeCarrierFallsBackToTheScalar(t *testing.T) {
	raw := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {"bom-ref": "pkg:npm/widget@1.0.0", "type": "library", "name": "widget",
     "version": "1.0.0", "purl": "pkg:npm/widget@1.0.0", "scope": "excluded",
     "properties": [{"name": "bomly:scopes", "value": "runtime,,nonsense"}]}
  ]
}`
	doc, _, err := UnmarshalAutoJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	got := componentScopes(t, doc, "widget")
	if len(got) != 1 || got[0] != sdk.ScopeDevelopment {
		t.Fatalf("scopes = %v, want the scalar's [development]", got)
	}
}

// The SPDX carrier is the same set format in a package comment, and reads back
// the same way.
func TestSPDXPackageCommentCarriesTheScopeSet(t *testing.T) {
	g := scopedGraph(t, sdk.ScopeRuntime, sdk.ScopeDevelopment)
	raw, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(string(raw), "scope=development,runtime") {
		t.Fatalf("the package comment does not carry the sorted set:\n%s", raw)
	}
}

// TestAnUnscopedForeignComponentSurvivesARuntimeFilter covers the case the
// fixtures did not: a document that omits `scope` entirely. Both halves of the
// answer matter and they come from different rules.
//
// Ingest applies CycloneDX's own instruction to a consumer -- scope "SHOULD be
// assumed" to be `required` when it is not specified -- so the component
// arrives scoped runtime rather than unscoped (bomly-dev/bomly-sdk#63).
// Filtering then keeps it, because a runtime view keeps everything not
// affirmatively development (ADR-0043). Before both, an unscoped component
// reached the graph with no scope and `--scope runtime` dropped it, so a scan
// of such a document could report clean because the filter had emptied it.
func TestAnUnscopedForeignComponentSurvivesARuntimeFilter(t *testing.T) {
	raw := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {"bom-ref": "pkg:npm/widget@1.0.0", "type": "library", "name": "widget",
     "version": "1.0.0", "purl": "pkg:npm/widget@1.0.0"}
  ]
}`
	doc, _, err := UnmarshalAutoJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := componentScopes(t, doc, "widget"); len(got) != 1 || got[0] != sdk.ScopeRuntime {
		t.Fatalf("scopes = %v, want [runtime]: an unspecified scope takes the specification's default", got)
	}

	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	filtered, report, err := sdk.FilterGraphByScopeWithReport(graph, sdk.ScopeRuntime)
	if err != nil {
		t.Fatalf("scope filter: %v", err)
	}
	if len(filtered.DependencyNodes()) != 1 {
		t.Fatalf("a runtime filter kept %d dependencies, want the unscoped component retained",
			len(filtered.DependencyNodes()))
	}
	// Ingest answered the scope, so the filter had something to narrow on and
	// nothing was kept merely because it asserted nothing.
	if len(report.Unasserted) != 0 {
		t.Errorf("report = %v, want empty: the CycloneDX default already scoped the component", report.Unasserted)
	}
}

// The SPDX half of the same question. SPDX has no scope concept, so a document
// Bomly did not write carries no scope for any package and none of them can be
// defaulted at ingest the way a CycloneDX component is -- SPDX issues no such
// instruction, and inventing one would put a claim in the model that no
// document made. The filter is what keeps these packages visible, and it
// reports that it narrowed nothing (ADR-0043).
func TestUnscopedSPDXPackagesSurviveARuntimeFilterAndAreReported(t *testing.T) {
	raw := `{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "foreign",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "https://example.com/foreign",
  "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: other-tool"]},
  "packages": [
    {"SPDXID": "SPDXRef-Package-widget", "name": "widget", "versionInfo": "1.0.0",
     "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": "pkg:npm/widget@1.0.0"}]}
  ]
}`
	doc, _, err := UnmarshalAutoJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := componentScopes(t, doc, "widget"); len(got) != 0 {
		t.Fatalf("scopes = %v, want none: SPDX asserts no scope and Bomly must not invent one", got)
	}

	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	filtered, report, err := sdk.FilterGraphByScopeWithReport(graph, sdk.ScopeRuntime)
	if err != nil {
		t.Fatalf("scope filter: %v", err)
	}
	if len(filtered.DependencyNodes()) != 1 {
		t.Fatalf("a runtime filter kept %d dependencies of an SPDX document, want the package retained",
			len(filtered.DependencyNodes()))
	}
	if len(report.Unasserted) != 1 {
		t.Errorf("report = %v, want the one package named: the filter narrowed nothing and must say so", report.Unasserted)
	}
}
