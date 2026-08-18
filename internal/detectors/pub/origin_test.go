package pub

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
)

// A pubspec.lock hosted package's description URL is the pub server, shared by
// every hosted package, and a path package is local. Only a git package names
// where its own code came from.
func TestPubOriginBySourceType(t *testing.T) {
	lock := []byte(`packages:
  collection:
    dependency: transitive
    description:
      name: collection
      sha256: abc
      url: "https://pub.dev"
    source: hosted
    version: "1.18.0"
  corp_widgets:
    dependency: transitive
    description:
      name: corp_widgets
      sha256: def
      url: "https://dart.corp/internal/feed"
    source: hosted
    version: "3.1.0"
  helper:
    dependency: "direct main"
    description:
      url: "https://github.com/example/helper.git"
      ref: main
      resolved-ref: a3b4c5d6e7f8091a2b3c4d5e6f70819213243546
      path: "."
    source: git
    version: "2.0.0"
  local_tools:
    dependency: "direct dev"
    description:
      path: "../local_tools"
      relative: true
    source: path
    version: "0.1.0"
`)
	manifest := pubspec{
		Name:            "demo",
		Version:         "1.0.0",
		Dependencies:    map[string]any{"helper": "any"},
		DevDependencies: map[string]any{"local_tools": "any"},
	}

	graph, err := depGraphFromLock(lock, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}

	cases := []struct {
		id   string
		want detectors.Origin
	}{
		{id: "collection@1.18.0"},
		// A self-hosted pub server's URL has a path, so nothing but the
		// source kind distinguishes it from a repository URL.
		{id: "corp_widgets@3.1.0"},
		{id: "helper@2.0.0", want: detectors.Origin{
			VCSURL:      "https://github.com/example/helper.git",
			VCSRevision: "a3b4c5d6e7f8091a2b3c4d5e6f70819213243546",
		}},
		{id: "local_tools@0.1.0"},
	}
	for _, tc := range cases {
		node, ok := graph.Node(tc.id)
		if !ok {
			t.Fatalf("expected %s in graph", tc.id)
		}
		if got := detectors.OriginFrom(node.Metadata); got != tc.want {
			t.Errorf("%s origin = %+v, want %+v", tc.id, got, tc.want)
		}
	}
}
