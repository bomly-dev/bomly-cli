package sbom

import (
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

// TestOrgSurvivesACycloneDXRoundTripOnlyWhereItExists pins done-criterion 2
// of the SDK maturity program (dev-docs/SDK_MATURITY_PLAN.md §6, issue #455)
// as a test rather than a one-off measurement: a package whose module path
// carries an organization segment keeps its org through export → ingest →
// export, and a package whose path has none gains none. The second half is
// what the original "24/24" framing got wrong -- a self-scan of this
// repository holds `go4.org`, a module with no organization to preserve, and
// counting it as a loss made a correct round trip look like a defect.
func TestOrgSurvivesACycloneDXRoundTripOnlyWhereItExists(t *testing.T) {
	g := sdk.New()
	withOrg := testnodes.Dep(sdk.Coordinates{
		Ecosystem: sdk.EcosystemGo,
		Org:       "github.com/spf13",
		Name:      "cobra",
		Version:   "v1.8.0",
	})
	withoutOrg := testnodes.Dep(sdk.Coordinates{
		Ecosystem: sdk.EcosystemGo,
		Name:      "go4.org",
		Version:   "v0.0.0-20230225012048-214862532bf5",
	})
	for _, node := range []*sdk.DependencyNode{withOrg, withoutOrg} {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("add node: %v", err)
		}
	}

	first, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	doc, _, err := UnmarshalAutoJSON(first)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	ingested, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("graph: %v", err)
	}

	cases := []struct {
		node     *sdk.DependencyNode
		wantOrg  string
		wantName string
	}{
		{node: withOrg, wantOrg: "github.com/spf13", wantName: "github.com/spf13/cobra"},
		{node: withoutOrg, wantOrg: "", wantName: "go4.org"},
	}
	for _, tc := range cases {
		got, ok := ingested.DependencyNode(tc.node.NodeID())
		if !ok {
			t.Fatalf("%s did not survive ingest; graph holds %d nodes", tc.node.NodeID(), ingested.Size())
		}
		if got.Org != tc.wantOrg {
			t.Errorf("%s: org = %q after the round trip, want %q", tc.node.NodeID(), got.Org, tc.wantOrg)
		}
		if name := got.EcosystemName(); name != tc.wantName {
			t.Errorf("%s: name = %q after the round trip, want %q (no doubled or lost namespace)", tc.node.NodeID(), name, tc.wantName)
		}
	}

	// And the second hop writes the same groups the first did.
	second, err := MarshalDepGraphJSON(ingested, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("re-export: %v", err)
	}
	groups := func(raw []byte) map[string]string {
		var bom cdx.BOM
		if err := json.Unmarshal(raw, &bom); err != nil {
			t.Fatalf("decode: %v", err)
		}
		out := map[string]string{}
		if bom.Components != nil {
			for _, component := range *bom.Components {
				out[component.PackageURL] = component.Group
			}
		}
		return out
	}
	before, after := groups(first), groups(second)
	if len(before) != 2 || len(after) != 2 {
		t.Fatalf("component sets differ across hops: %v then %v", before, after)
	}
	for purl, group := range before {
		if after[purl] != group {
			t.Errorf("%s: group %q became %q on the second hop", purl, group, after[purl])
		}
	}
	if before[withOrg.NodeID()] != "github.com/spf13" || before[withoutOrg.NodeID()] != "" {
		t.Errorf("first hop groups = %v, want the org written exactly where one exists", before)
	}
}
