package conan

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzDepGraphFromConanJSON(f *testing.F) {
	f.Add([]byte(`{"graph":{"nodes":{"0":{"ref":"app/1.0","requires":{"1":"dep/2.0"}},"1":{"ref":"dep/2.0"}}}}`))
	f.Add([]byte(`{"graph":`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromJSON(data)
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
