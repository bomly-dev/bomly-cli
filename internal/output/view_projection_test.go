package output

import (
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

func TestProjectedDependencyDetailReviewReasonsMatchCanonicalTransition(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	before := sdk.NewDependencyWithID("npm:example", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			PURL:    purl,
			Name:    "example",
			Version: "1.0.0",
		},
		Source:     sdk.DependencySourceRegistry,
		PackageRef: purl,
	})
	for _, source := range []sdk.DependencySource{
		sdk.DependencySourceGit,
		sdk.DependencySourceURL,
	} {
		t.Run(string(source), func(t *testing.T) {
			after := before.Clone()
			after.Source = source
			canonical := sdk.DependencyDetailTransition{
				Before:                 before,
				After:                  after,
				ChangedFields:          []sdk.DependencyDetailField{sdk.DependencyDetailSource, sdk.DependencyDetailRegistryEligibility},
				BeforeRegistryEligible: true,
				AfterRegistryEligible:  false,
			}
			projected := diffDependencyTransitionsFromDiff([]sdk.DependencyDetailTransition{canonical})
			if len(projected) != 1 {
				t.Fatalf("projected transitions = %#v, want one", projected)
			}
			if got, want := DependencyDetailReviewReasons(projected[0]), canonical.ReviewReasons(); !reflect.DeepEqual(got, want) {
				t.Fatalf("projected review reasons = %#v, want canonical %#v", got, want)
			}
		})
	}
}
