package swiftpm

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
)

// A Package.resolved pin says how SwiftPM obtained a package. Source-control
// pins name a repository and the commit that was resolved; registry pins are
// identity-only; local pins point at a checkout on this machine.
func TestSwiftPMOriginByPinKind(t *testing.T) {
	resolved := []byte(`{
      "pins": [
        {
          "identity": "swift-argument-parser",
          "kind": "remoteSourceControl",
          "location": "https://github.com/apple/swift-argument-parser.git",
          "state": {"revision": "8192a3b4c5d6e7f8091a2b3c4d5e6f7081921324", "version": "1.3.0"}
        },
        {
          "identity": "internal-tools",
          "kind": "registry",
          "state": {"version": "2.0.0"}
        },
        {
          "identity": "local-helper",
          "kind": "localSourceControl",
          "location": "/Users/someone/src/local-helper",
          "state": {"revision": "92a3b4c5d6e7f8091a2b3c4d5e6f708192132435", "version": "0.1.0"}
        }
      ],
      "version": 2
    }`)

	graph, err := depGraphFromSwiftPM(resolved, nil)
	if err != nil {
		t.Fatalf("depGraphFromSwiftPM() error = %v", err)
	}

	var checked int
	for _, node := range graph.Nodes() {
		origin := detectors.OriginFrom(node.Metadata)
		switch node.Name {
		case "swift-argument-parser":
			checked++
			want := detectors.Origin{
				VCSURL:      "https://github.com/apple/swift-argument-parser.git",
				VCSRevision: "8192a3b4c5d6e7f8091a2b3c4d5e6f7081921324",
			}
			if origin != want {
				t.Errorf("%s origin = %+v, want %+v", node.Name, origin, want)
			}
		case "internal-tools", "local-helper":
			checked++
			if !origin.Empty() {
				t.Errorf("%s asserted an origin it should not have: %+v", node.Name, origin)
			}
		}
	}
	if checked != 3 {
		t.Fatalf("checked %d pins, want 3", checked)
	}
}
