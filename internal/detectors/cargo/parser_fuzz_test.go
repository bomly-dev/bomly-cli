package cargo

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func FuzzDepGraphFromCargoLock(f *testing.F) {
	f.Add(
		[]byte("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n"),
		[]byte("[package]\nname = \"fuzz-root\"\nversion = \"1.0.0\"\n[dependencies]\nserde = \"1\"\n"),
	)
	f.Add([]byte("[[package]\n"), []byte("[package\n"))
	f.Fuzz(func(t *testing.T, lockRaw, manifestRaw []byte) {
		if len(lockRaw)+len(manifestRaw) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromLockWithScope(lockRaw, manifestRaw, sdk.Scope(""))
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
