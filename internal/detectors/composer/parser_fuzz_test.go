package composer

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzDepGraphFromComposerLock(f *testing.F) {
	f.Add([]byte(`{"packages":[{"name":"vendor/pkg","version":"1.2.3","require":{}}],"packages-dev":[]}`))
	f.Add([]byte(`{"packages":`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromLock(data, composerManifest{})
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
