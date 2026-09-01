package ruby

import (
	"github.com/bomly-dev/bomly-sdk"
	"testing"
)

// originOf returns the origin a node publishes, or the zero value when it has
// none, so cases can compare plain structs.
func originOf(dep *sdk.DependencyNode) sdk.DependencyOrigin {
	if dep == nil {
		return sdk.DependencyOrigin{}
	}
	if origin := dep.Origin.Normalized(); origin != nil {
		return *origin
	}
	return sdk.DependencyOrigin{}
}

// A Gemfile.lock names its sources by section. GEM's remote is the gem server
// every gem in that section came from, not a per-gem location; PATH is a
// directory on the machine that ran bundle install. Only GIT identifies where
// a specific gem's code came from.
func TestBundlerOriginBySection(t *testing.T) {
	raw := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    rack (3.1.8)

GEM
  remote: https://gems.corp/private/feed/
  specs:
    corp-auth (2.4.0)

GIT
  remote: https://github.com/example/helper.git
  revision: 708192a3b4c5d6e7f8091a2b3c4d5e6f70819213
  specs:
    helper (1.0.0)

PATH
  remote: ../local-gem
  specs:
    local-gem (0.1.0)

DEPENDENCIES
  corp-auth
  helper!
  local-gem!
  rack
`)

	graph, err := depGraphFromLock(raw, nil)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}

	cases := []struct {
		id   string
		want sdk.DependencyOrigin
	}{
		{id: "rack@3.1.8"},
		// A private gem server's remote has a path, so nothing but the
		// section kind distinguishes it from a repository URL.
		{id: "corp-auth@2.4.0"},
		{id: "helper@1.0.0", want: sdk.DependencyOrigin{
			Repository: "https://github.com/example/helper.git",
			Revision:   "708192a3b4c5d6e7f8091a2b3c4d5e6f70819213",
		}},
		{id: "local-gem@0.1.0"},
	}
	for _, tc := range cases {
		node, ok := graph.Node(tc.id)
		if !ok {
			t.Fatalf("expected %s in graph", tc.id)
		}
		if got := originOf(node); got != tc.want {
			t.Errorf("%s origin = %+v, want %+v", tc.id, got, tc.want)
		}
	}
}
