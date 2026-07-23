package cocoapods

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzDepGraphFromPodfileLock(f *testing.F) {
	f.Add([]byte("PODS:\n  - AFNetworking (4.0.1)\nDEPENDENCIES:\n  - AFNetworking\n"))
	f.Add([]byte("PODS: ["))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromLock(data, nil)
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
