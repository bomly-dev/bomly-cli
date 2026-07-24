package mix

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzDepGraphFromMixLock(f *testing.F) {
	f.Add(
		[]byte(`%{"plug" => {:hex, :plug, "1.15.0", "hash", [:mix], [], "hexpm", "checksum"}}`),
		[]byte(`defp deps do [{:plug, "~> 1.15"}] end`),
	)
	f.Add([]byte("%{"), []byte("defp deps"))
	f.Fuzz(func(t *testing.T, lockRaw, manifestRaw []byte) {
		if len(lockRaw)+len(manifestRaw) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromMix(lockRaw, manifestRaw)
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
