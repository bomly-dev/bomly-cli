package output

import (
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
)

func TestProjectedDependencyDetailReviewReasonsMatchCanonicalTransition(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	before := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{
			PURL:    purl,
			Name:    "example",
			Version: "1.0.0",
		},
		Source:     model.DependencySourceRegistry,
		PackageRef: purl,
	})
	for _, source := range []model.DependencySource{
		model.DependencySourceGit,
		model.DependencySourceURL,
	} {
		t.Run(string(source), func(t *testing.T) {
			after := before.Clone()
			after.Source = source
			canonical := model.DependencyDetailTransition{
				Before:                 before,
				After:                  after,
				ChangedFields:          []model.DependencyDetailField{model.DependencyDetailSource, model.DependencyDetailRegistryEligibility},
				BeforeRegistryEligible: true,
				AfterRegistryEligible:  false,
			}
			projected := diffDependencyTransitionsFromDiff([]model.DependencyDetailTransition{canonical})
			if len(projected) != 1 {
				t.Fatalf("projected transitions = %#v, want one", projected)
			}
			if got, want := DependencyDetailReviewReasons(projected[0]), canonical.ReviewReasons(); !reflect.DeepEqual(got, want) {
				t.Fatalf("projected review reasons = %#v, want canonical %#v", got, want)
			}
		})
	}
}
