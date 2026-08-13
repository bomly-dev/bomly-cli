package jsreach

import (
	"encoding/json"
	"reflect"
	"testing"

	testutil "github.com/bomly-dev/bomly-sdk/testkit"
)

// FuzzEntryPointStrings verifies that the package.json entry-point
// helpers never panic and produce deterministic output for arbitrary
// (valid, malformed, or truncated) JSON input within the shared fuzz
// input bound. The helpers tolerate any shape by design, so every
// input is expected to succeed; determinism is the real contract —
// walkJSONStrings and binEntryStrings walk JSON objects, and emission
// order must not depend on Go's randomized map iteration.
func FuzzEntryPointStrings(f *testing.F) {
	for _, seed := range []string{
		`"./index.js"`,
		`{"my-cli": "./cli.js", "other": "./other.js"}`,
		`{".": {"import": "./esm/index.js", "require": "./cjs/index.js"}, "./util": "./util.js"}`,
		`["./a.js", {"b": "./b.js"}, ["./c.js"]]`,
		`{"browser": {"./fs": false}}`,
		`{"unterminated": "./x.js"`,
		`null`,
		`42`,
		``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		raw := json.RawMessage(data)
		helpers := map[string]func(json.RawMessage) []string{
			"browserEntryStrings": browserEntryStrings,
			"exportsEntryStrings": exportsEntryStrings,
			"binEntryStrings":     binEntryStrings,
		}
		for name, helper := range helpers {
			first := helper(raw)
			second := helper(raw)
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("%s changed result for identical input: first=%v second=%v", name, first, second)
			}
		}
	})
}
