package ruby

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func FuzzDepGraphFromBundlerLock(f *testing.F) {
	f.Add([]byte("GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.2.1)\n\nDEPENDENCIES\n  rake\n"))
	f.Add([]byte("GEM\n  specs:\n    broken ("))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromLock(data, map[string]sdk.Scope{})
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
