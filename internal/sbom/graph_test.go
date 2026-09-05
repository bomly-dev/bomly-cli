package sbom

import (
	"strings"
	"testing"
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
