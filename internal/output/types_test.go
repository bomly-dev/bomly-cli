package output_test

import (
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-sdk"
)

// A workspace reaches one lockfile line from several members, so the same path
// appears once per member. Without the attribution those records are
// byte-identical and the reader sees one file listed twice with no way to tell
// why -- which is what this projection produced before it carried them.
func TestLocationRefsCarryTheAttributionThatDistinguishesThem(t *testing.T) {
	refs := output.LocationRefsFromGraphLocations([]sdk.PackageLocation{
		{
			RealPath:     "package-lock.json",
			ModuleRoot:   "apps/web",
			Scopes:       []sdk.Scope{sdk.ScopeDevelopment},
			Relationship: sdk.DependencyRelationshipDirect,
		},
		{
			RealPath:     "package-lock.json",
			ModuleRoot:   "packages/lib",
			Scopes:       []sdk.Scope{sdk.ScopeRuntime},
			Relationship: sdk.DependencyRelationshipTransitive,
		},
	})
	if len(refs) != 2 {
		t.Fatalf("refs = %d, want both usages", len(refs))
	}
	if reflect.DeepEqual(refs[0], refs[1]) {
		t.Fatal("two usages of one path are indistinguishable in the output")
	}
	if refs[0].ModuleRoot != "apps/web" || refs[0].Relationship != "direct" ||
		len(refs[0].Scopes) != 1 || refs[0].Scopes[0] != "development" {
		t.Errorf("first usage = %+v", refs[0])
	}
	if refs[1].ModuleRoot != "packages/lib" || refs[1].Relationship != "transitive" {
		t.Errorf("second usage = %+v", refs[1])
	}
}

// A site with no path is still worth reporting when it says which module
// reached the package and how.
func TestAnAttributedSiteWithNoPathIsKept(t *testing.T) {
	refs := output.LocationRefsFromGraphLocations([]sdk.PackageLocation{
		{ModuleRoot: "apps/web", Relationship: sdk.DependencyRelationshipDirect},
		{},
	})
	if len(refs) != 1 {
		t.Fatalf("refs = %d, want the attributed site kept and the empty one dropped", len(refs))
	}
	if refs[0].ModuleRoot != "apps/web" {
		t.Errorf("ref = %+v", refs[0])
	}
}
