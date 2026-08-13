package pyreach

import (
	"bytes"
	"reflect"
	"testing"

	testutil "github.com/bomly-dev/bomly-sdk/testkit"
)

// FuzzScanImports verifies that the Python import scanner never panics
// and produces deterministic results for arbitrary (valid, malformed, or
// truncated) source input within the shared fuzz input bound.
func FuzzScanImports(f *testing.F) {
	for _, seed := range []string{
		"",
		"import os\nimport requests, flask\nfrom django.db import models\n",
		"\"\"\"docstring\nimport hidden\n\"\"\"\nimport real  # trailing \"\"\" comment\n",
		"from . import sibling\nfrom .. import parent\nimport a.b.c as abc\n",
		"import unterminated\nx = '''\nimport swallowed\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		first, firstErr := scanImports(bytes.NewReader(data))
		second, secondErr := scanImports(bytes.NewReader(data))
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("scan changed success state: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("scan changed result for identical input")
		}
	})
}
