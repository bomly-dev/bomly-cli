package support

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/composition"
	"github.com/bomly-dev/bomly-sdk"
)

// TestCompositionMatcherEntriesHaveProse asserts that every composed matcher
// name is covered by the handwritten docs catalog: composition entry names
// must stay a subset of the prose file names so generated component docs
// never reference an undocumented built-in.
func TestCompositionMatcherEntriesHaveProse(t *testing.T) {
	files, err := proseFS.ReadDir("prose/matchers")
	if err != nil {
		t.Fatalf("read matcher prose: %v", err)
	}
	documented := map[string]bool{}
	for _, file := range files {
		name := file.Name()
		if len(name) > 3 && name[len(name)-3:] == ".md" {
			documented[name[:len(name)-3]] = true
		}
	}
	for _, entry := range composition.Entries() {
		if entry.Kind != sdk.PluginKindMatcher {
			continue
		}
		if !documented[entry.Name] {
			t.Errorf("composition matcher %q has no prose page under internal/support/prose/matchers", entry.Name)
		}
	}
}
