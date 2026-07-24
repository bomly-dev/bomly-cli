package jsreach

import (
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzExtractImportedPackages(f *testing.F) {
	for _, seed := range []string{
		`{"inputs":{}}`,
		`{"inputs":{"src/main.js":{"imports":[{"path":"react/jsx-runtime","external":true},{"path":"@scope/pkg/subpath","external":true}]}}}`,
		`{"inputs":{"../../node_modules/pkg/index.js":{"imports":[]},"src/main.js":{"imports":[{"path":"node:fs"},{"path":"../local.js"}]}}}`,
		`{`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		first, firstCount, firstErr := extractImportedPackages(data)
		second, secondCount, secondErr := extractImportedPackages(data)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("parse changed success state: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatalf("parse changed error: first=%v second=%v", firstErr, secondErr)
			}
			return
		}
		if firstCount != secondCount || !reflect.DeepEqual(first, second) {
			t.Fatal("parse changed result for identical input")
		}
	})
}
