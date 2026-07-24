package swiftpm

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzDepGraphFromSwiftResolved(f *testing.F) {
	f.Add(
		[]byte(`{"version":2,"pins":[{"identity":"swift-argument-parser","kind":"remoteSourceControl","location":"https://github.com/apple/swift-argument-parser","state":{"revision":"abc","version":"1.5.0"}}]}`),
		[]byte(`.package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0")`),
	)
	f.Add([]byte(`{"pins":`), []byte(`.package(`))
	f.Fuzz(func(t *testing.T, resolvedRaw, manifestRaw []byte) {
		if len(resolvedRaw)+len(manifestRaw) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromSwiftPM(resolvedRaw, manifestRaw)
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
