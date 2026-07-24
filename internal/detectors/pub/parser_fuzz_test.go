package pub

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzDepGraphFromPubLock(f *testing.F) {
	f.Add([]byte("packages:\n  collection:\n    dependency: direct main\n    description:\n      name: collection\n      url: https://pub.dev\n    source: hosted\n    version: 1.18.0\n"))
	f.Add([]byte("packages: ["))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromLock(data, pubspec{})
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
