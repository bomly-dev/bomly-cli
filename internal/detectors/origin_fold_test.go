package detectors_test

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

func TestFoldOrigin(t *testing.T) {
	const (
		public  = "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
		mirror  = "https://npm.corp/mirror/react/-/react-18.2.0.tgz"
		repoURL = "https://github.com/facebook/react"
	)
	withArtifact := func(url string) *sdk.Dependency {
		dep := &sdk.Dependency{ID: "react@18.2.0"}
		if url != "" {
			dep.Origin = sdk.ArtifactOrigin(url)
		}
		return dep
	}

	cases := []struct {
		name     string
		survivor *sdk.Dependency
		replaced *sdk.Dependency
		want     sdk.PackageOrigin
	}{
		{name: "records agree", survivor: withArtifact(public), replaced: withArtifact(public), want: sdk.PackageOrigin{ArtifactURL: public}},
		{name: "records disagree", survivor: withArtifact(public), replaced: withArtifact(mirror)},
		{name: "the replaced record fills a gap", survivor: withArtifact(""), replaced: withArtifact(public), want: sdk.PackageOrigin{ArtifactURL: public}},
		{name: "the replaced record says nothing", survivor: withArtifact(public), replaced: withArtifact(""), want: sdk.PackageOrigin{ArtifactURL: public}},
		{
			name:     "different kinds disagree",
			survivor: withArtifact(public),
			replaced: func() *sdk.Dependency {
				dep := &sdk.Dependency{ID: "react@18.2.0"}
				dep.Origin = sdk.RepositoryOrigin(repoURL, "")
				return dep
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detectors.FoldOrigin(tc.survivor, tc.replaced)
			got := sdk.PackageOrigin{}
			if origin := tc.survivor.Origin.Normalized(); origin != nil {
				got = *origin
			}
			if got != tc.want {
				t.Fatalf("folded origin = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Callers fold in whichever direction their data structure demands: a graph
// keeps the node already present, a name index keeps the incoming one. The
// outcome must not depend on which they pass first.
func TestFoldOriginIsSymmetric(t *testing.T) {
	const (
		public = "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
		mirror = "https://npm.corp/mirror/react/-/react-18.2.0.tgz"
	)
	build := func(url string) *sdk.Dependency {
		dep := &sdk.Dependency{ID: "react@18.2.0"}
		if url != "" {
			dep.Origin = sdk.ArtifactOrigin(url)
		}
		return dep
	}

	for _, pair := range [][2]string{{public, mirror}, {public, ""}, {"", public}, {public, public}} {
		forward, backward := build(pair[0]), build(pair[1])
		detectors.FoldOrigin(forward, build(pair[1]))
		detectors.FoldOrigin(backward, build(pair[0]))

		left, right := forward.Origin.Normalized(), backward.Origin.Normalized()
		switch {
		case left == nil && right == nil:
		case left == nil || right == nil:
			t.Fatalf("folding %v in each direction gave %+v and %+v", pair, left, right)
		case *left != *right:
			t.Fatalf("folding %v in each direction gave %+v and %+v", pair, left, right)
		}
	}
}

func TestFoldOriginNilIsANoOp(t *testing.T) {
	dep := &sdk.Dependency{ID: "react@18.2.0"}
	dep.Origin = sdk.ArtifactOrigin("https://registry.npmjs.org/react/-/react-18.2.0.tgz")
	detectors.FoldOrigin(dep, nil)
	detectors.FoldOrigin(nil, dep)

	if origin := dep.Origin.Normalized(); origin == nil {
		t.Fatal("folding against nil dropped the origin")
	}
}

// The project's own code has no external origin. Folding treats absence as a
// gap to fill, so without this a published package sharing a workspace member's
// name and version would hand over its download location.
func TestFoldOriginLeavesFirstPartyCodeAlone(t *testing.T) {
	external := func() *sdk.Dependency {
		dep := &sdk.Dependency{ID: "lib@1.0.0"}
		dep.Origin = sdk.ArtifactOrigin("https://registry.npmjs.org/lib/-/lib-1.0.0.tgz")
		return dep
	}

	t.Run("a flagged first-party node takes nothing", func(t *testing.T) {
		member := &sdk.Dependency{ID: "lib@1.0.0", Coordinates: sdk.Coordinates{FirstParty: true}}
		detectors.FoldOrigin(member, external())

		if origin := member.Origin.Normalized(); origin != nil {
			t.Fatalf("workspace member claims %+v", origin)
		}
	})

	t.Run("an application node takes nothing", func(t *testing.T) {
		member := &sdk.Dependency{ID: "lib@1.0.0", Coordinates: sdk.Coordinates{Type: sdk.PackageTypeApplication}}
		detectors.FoldOrigin(member, external())

		if origin := member.Origin.Normalized(); origin != nil {
			t.Fatalf("application node claims %+v", origin)
		}
	})

	// The reverse direction is unaffected: a consumed package still folds.
	t.Run("a consumed package still folds", func(t *testing.T) {
		pkg := &sdk.Dependency{ID: "lib@1.0.0"}
		detectors.FoldOrigin(pkg, external())

		if origin := pkg.Origin.Normalized(); origin == nil {
			t.Fatal("a consumed package should still take the folded origin")
		}
	})
}
