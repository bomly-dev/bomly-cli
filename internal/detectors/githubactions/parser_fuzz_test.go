package githubactions

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzParseWorkflowRefs(f *testing.F) {
	for _, seed := range []string{
		"name: CI\non: push\njobs:\n  test:\n    uses: owner/repo/.github/workflows/reusable.yml@v1\n",
		"name: CI\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/local\n",
		"jobs: [",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		path := filepath.Join(t.TempDir(), "workflow.yml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		first, firstErr := parseWorkflowRefs(path)
		second, secondErr := parseWorkflowRefs(path)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("parse changed success state: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr == nil && !reflect.DeepEqual(first, second) {
			t.Fatal("parse changed result for identical input")
		}
	})
}
