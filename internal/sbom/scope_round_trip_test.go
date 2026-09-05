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
func TestForeignCycloneDXScopesMapIntoTheSDKVocabulary(t *testing.T) {
	for _, testCase := range []struct {
		native string
		want   sdk.Scope
	}{
		{"required", sdk.ScopeRuntime},
		{"optional", sdk.ScopeRuntime},
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
