package sbom

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

// An SBOM component whose identity cannot mint a well-formed package URL
// fails the conversion instead of disappearing from it.
//
// This used to `continue`: the component was dropped along with every
// relationship naming it, ToGraph returned no error, and a scan of that
// document reported a smaller graph than the document described. For a tool
// whose answer is "what are you shipping and is it vulnerable", quietly
// returning fewer dependencies than the input listed is the worst available
// failure -- a genuinely vulnerable package can be absent while the scan
// reads clean.
func TestToGraphRefusesAComponentWithNoUsableIdentity(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{ID: "c1", Name: "good", Version: "1.0.0", PURL: "pkg:npm/good@1.0.0"},
			// The maven type requires a namespace; this states one that has
			// none, so the identity is asserted and invalid rather than absent.
			{ID: "c2", Name: "bad", Version: "2.0.0", PURL: "pkg:maven/bad@2.0.0"},
		},
		Dependencies: []Dependency{{Ref: "c1", DependsOn: []string{"c2"}}},
	}

	g, err := ToGraph(doc)
	if err == nil {
		t.Fatalf("ToGraph accepted an unusable identity and returned a graph of %d nodes; "+
			"a dropped component is a dependency missing from the scan", g.Size())
	}
	// The message has to name the offending component: the fix is in the
	// author's document, not here.
	for _, want := range []string{"c2", "pkg:maven/bad@2.0.0"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err, want)
		}
	}
}

// A well-formed document still converts, so the refusal is scoped to
// identities that genuinely cannot be minted.
func TestToGraphAcceptsWellFormedComponents(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{ID: "c1", Name: "good", Version: "1.0.0", PURL: "pkg:npm/good@1.0.0"},
			{ID: "c2", Name: "core", Version: "2.0.0", PURL: "pkg:maven/org.acme/core@2.0.0"},
		},
		Dependencies: []Dependency{{Ref: "c1", DependsOn: []string{"c2"}}},
	}

	g, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("ToGraph() error = %v", err)
	}
	if g.Size() != 2 {
		t.Fatalf("graph size = %d, want both components:\n%s", g.Size(), g.PrettyString())
	}
	deps, err := g.DirectDependencies("pkg:npm/good@1.0.0")
	if err != nil {
		t.Fatalf("DirectDependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0].NodeID() != "pkg:maven/org.acme/core@2.0.0" {
		t.Fatalf("edges = %#v, want the declared relationship preserved", deps)
	}
}

// An SBOM must never name a bom-ref it does not define.
//
// A workspace is module -> child manifest -> child module, and the two edges
// are typed differently: the first derives depends-on, the second describes.
// Publishing the first named the manifest, which is not a component, so
// CycloneDX carried a dependsOn pointing at nothing; filtering the second
// dropped the hop, so the child module came loose from its parent. Both are
// fixed by contracting the path through the structural node.
func TestExportedDependenciesNameOnlyComponents(t *testing.T) {
	g := sdk.New()
	root := testnodes.Module("package.json", "workspace-root", "1.0.0")
	childManifest := testnodes.Manifest("packages/web/package.json", sdk.ManifestKindPackageJSON)
	child := testnodes.ModuleFrom("packages/web/package.json", sdk.Coordinates{
		Ecosystem: "npm", Name: "web", Version: "1.0.0",
	})
	leaf := testnodes.Dep(sdk.Coordinates{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	for _, node := range []sdk.GraphNode{root, childManifest, child, leaf} {
		if _, err := g.InsertNode(node); err != nil {
			t.Fatalf("InsertNode(%q): %v", node.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{
		{root.NodeID(), childManifest.NodeID()},
		{childManifest.NodeID(), child.NodeID()},
		{child.NodeID(), leaf.NodeID()},
	} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("AddEdge(%q -> %q): %v", edge[0], edge[1], err)
		}
	}

	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		t.Fatalf("decode cyclonedx: %v", err)
	}

	refs := map[string]struct{}{}
	if bom.Components != nil {
		for _, component := range *bom.Components {
			refs[component.BOMRef] = struct{}{}
		}
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		refs[bom.Metadata.Component.BOMRef] = struct{}{}
	}
	if _, listed := refs[childManifest.NodeID()]; listed {
		t.Fatalf("the manifest was exported as a component")
	}

	reached := map[string][]string{}
	if bom.Dependencies != nil {
		for _, dependency := range *bom.Dependencies {
			if dependency.Dependencies == nil {
				continue
			}
			for _, ref := range *dependency.Dependencies {
				if _, ok := refs[ref]; !ok {
					t.Fatalf("%q dependsOn %q, which is not a component in this document",
						dependency.Ref, ref)
				}
			}
			reached[dependency.Ref] = *dependency.Dependencies
		}
	}
	// And the workspace path survives the contracted hop.
	if got := reached[root.NodeID()]; len(got) != 1 || got[0] != child.NodeID() {
		t.Fatalf("root dependsOn = %v, want the child module %q reached through the manifest",
			got, child.NodeID())
	}
	if got := reached[child.NodeID()]; len(got) != 1 || got[0] != leaf.NodeID() {
		t.Fatalf("child module dependsOn = %v, want %q", got, leaf.NodeID())
	}
}
