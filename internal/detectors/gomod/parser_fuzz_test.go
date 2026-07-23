package gomod

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func FuzzDepGraphFromGoList(f *testing.F) {
	f.Add([]byte("{\"ImportPath\":\"example.com/root\",\"Module\":{\"Path\":\"example.com/root\",\"Main\":true}}\n{\"ImportPath\":\"example.com/dep/pkg\",\"Module\":{\"Path\":\"example.com/dep\",\"Version\":\"v1.2.3\"}}\n"))
	f.Add([]byte("{"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromGoListWithScope(data, "example.com/root", nil, sdk.Scope(""))
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
