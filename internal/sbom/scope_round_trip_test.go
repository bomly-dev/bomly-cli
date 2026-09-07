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
// The "optional" row was the one place ADR-0037 and the shipped SDK disagreed:
// the ADR said development, the SDK read it as runtime. Resolved in the ADR's
// favour by bomly-dev/bomly-sdk#63, and the objection that made it a real
// question -- that development would hide a shipped component from
// --scope runtime -- was answered separately rather than waved away: an
// unasserted scope now reads as runtime, so a component nobody classified is
// no longer the one that disappears.
func TestForeignCycloneDXScopesMapIntoTheSDKVocabulary(t *testing.T) {
	for _, testCase := range []struct {
		native string
		want   sdk.Scope
	}{
		{"required", sdk.ScopeRuntime},
		{"optional", sdk.ScopeDevelopment},
		{"excluded", sdk.ScopeDevelopment},
		// Unasserted is runtime, which is what keeps a component nobody
		// classified from being filtered out of the shipped set.
		{"", sdk.ScopeRuntime},
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

// foreignCycloneDX is a document Bomly did not write: a native scalar scope
// and no carrier property beside it.
func foreignCycloneDX(scope string) string {
	return `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {"bom-ref": "pkg:npm/widget@1.0.0", "type": "library", "name": "widget",
     "version": "1.0.0", "purl": "pkg:npm/widget@1.0.0", "scope": "` + scope + `"}
  ]
}`
}

// cycloneDXComponentScope reads the scalar scope a rendered document wrote.
func cycloneDXComponentScope(t *testing.T, raw []byte) cdx.Scope {
	t.Helper()
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatalf("no components:\n%s", raw)
	}
	return (*bom.Components)[0].Scope
}

// A source document's own scope word comes back out unchanged.
//
// It could not before: the model had nowhere to keep a source-asserted scope
// beside the set it derives, so a component a document marked "optional" was
// re-exported as "required" -- a claim about shipping code that the source had
// deliberately not made (bomly-dev/bomly-sdk#57). Every word in CycloneDX's
// vocabulary is covered, including "excluded", which read as development and
// projected back to "excluded" by luck rather than by preservation.
func TestSourceScopeWordSurvivesACycloneDXRoundTrip(t *testing.T) {
	for _, word := range []string{"required", "optional", "excluded"} {
		t.Run(word, func(t *testing.T) {
			doc, _, err := UnmarshalAutoJSON([]byte(foreignCycloneDX(word)))
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			if got := componentNamed(t, doc, "widget").SourceScope; got != word {
				t.Fatalf("ingested source scope = %q, want %q", got, word)
			}

			g, err := ToGraph(doc)
			if err != nil {
				t.Fatalf("to graph: %v", err)
			}
			raw, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{Pretty: true})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			if got := cycloneDXComponentScope(t, raw); string(got) != word {
				t.Errorf("re-exported scope = %q, want the source's own word %q\n%s", got, word, raw)
			}
		})
	}
}

// When Bomly's own scope set no longer means what the source's word meant,
// the projection is written instead. The word is preserved, not obeyed: it
// describes a set, and a set that changed is no longer the one it describes.
func TestSourceScopeYieldsToTheProjectionWhenTheSetChanges(t *testing.T) {
	doc, _, err := UnmarshalAutoJSON([]byte(foreignCycloneDX("optional")))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	g, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	nodes := g.DependencyNodes()
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	// What propagation does when the package turns out to be reachable from a
	// runtime root as well: the set now says something "optional" does not.
	//
	// It has to be runtime specifically. "optional" already means development
	// on its own, so adding development leaves the set exactly what the word
	// described and the word is rightly re-emitted -- which is the case the
	// test above covers, not this one.
	nodes[0].Scopes = append(nodes[0].Scopes, sdk.ScopeRuntime)

	raw, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if got := cycloneDXComponentScope(t, raw); got != cdx.ScopeRequired {
		t.Errorf("scope = %q, want the projection %q once the set changed\n%s", got, cdx.ScopeRequired, raw)
	}
}

// A carrier naming one token this build does not know keeps the scopes it
// does know, and reports the token.
//
// The strict read was a forward-compatibility trap: one unknown token from a
// newer Bomly dropped the whole assertion. CycloneDX could fall back to its
// scalar; SPDX has no scalar, so the component ended up unscoped altogether --
// the loss bomly-dev/bomly-sdk#64 recorded.
func TestUnknownScopeTokenKeepsTheKnownScopes(t *testing.T) {
	spdxWithCarrier := `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "n",
  "documentNamespace": "https://acme.example/spdx/n",
  "creationInfo": {"created": "2026-01-02T03:04:05Z", "creators": ["Tool: t"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-widget",
      "name": "widget",
      "versionInfo": "1.0.0",
      "comment": "bomly:scope=runtime,future-scope",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/widget@1.0.0"}
      ]
    }
  ]
}`
	cycloneDXWithCarrier := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {"bom-ref": "pkg:npm/widget@1.0.0", "type": "library", "name": "widget",
     "version": "1.0.0", "purl": "pkg:npm/widget@1.0.0", "scope": "excluded",
     "properties": [{"name": "bomly:scopes", "value": "runtime,future-scope"}]}
  ]
}`
	for name, raw := range map[string]string{"spdx": spdxWithCarrier, "cyclonedx": cycloneDXWithCarrier} {
		t.Run(name, func(t *testing.T) {
			doc, _, err := UnmarshalAutoJSON([]byte(raw))
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			got := componentScopes(t, doc, "widget")
			if len(got) != 1 || got[0] != sdk.ScopeRuntime {
				t.Fatalf("scopes = %v, want the token this build can read", got)
			}
			if len(doc.UnknownScopeTokens) != 1 || doc.UnknownScopeTokens[0] != "future-scope" {
				t.Errorf("unknown tokens = %v, want the one that was dropped", doc.UnknownScopeTokens)
			}
		})
	}
}

// A document Bomly wrote names no unknown tokens, so the warning stays quiet
// on the ordinary path.
func TestAKnownCarrierReportsNoUnknownTokens(t *testing.T) {
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
			if len(doc.UnknownScopeTokens) != 0 {
				t.Errorf("unknown tokens = %v, want none", doc.UnknownScopeTokens)
			}
		})
	}
}
