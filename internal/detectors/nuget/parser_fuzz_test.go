package nuget

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzDepGraphFromNuGetLock(f *testing.F) {
	f.Add([]byte(`{"version":1,"dependencies":{".NETCoreApp,Version=v8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.3","dependencies":{}}}}}`))
	f.Add([]byte(`{"dependencies":`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromLock(data)
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}

func FuzzDepGraphFromPackagesConfig(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><packages><package id="Newtonsoft.Json" version="13.0.3" targetFramework="net8.0" /></packages>`))
	f.Add([]byte(`<packages><package`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromPackagesConfig(data)
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
