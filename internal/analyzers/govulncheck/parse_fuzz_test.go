package govulncheck

import (
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzParseGovulncheckJSON(f *testing.F) {
	for _, seed := range []string{
		"",
		`{"osv":{"id":"GO-2026-0001","aliases":["CVE-2026-0001"]}}` + "\n" +
			`{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.2.3","trace":[{"module":"example.com/mod","package":"example.com/mod/pkg","function":"Call"}]}}`,
		"{\n{}\nnot-json\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		first, firstErr := parseGovulncheckJSON(data)
		second, secondErr := parseGovulncheckJSON(data)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("parse changed success state: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatalf("parse changed error: first=%v second=%v", firstErr, secondErr)
			}
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("parse changed result for identical input")
		}
	})
}
