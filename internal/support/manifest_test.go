package support

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// docs/manifest.json drives the landing page's per-version navigation. It must
// stay in 1:1 sync with the top-level user-facing docs in docs/ — every doc
// needs a manifest entry, and every manifest entry needs a doc — so the nav
// can't silently drift from the docs themselves. Nested docs (detectors/,
// matchers/, schemas/, auditors/, plugins/, …) are auto-discovered by the
// renderer and are intentionally not listed in the manifest.
func TestDocsManifestMatchesTopLevelDocs(t *testing.T) {
	docsDir := filepath.Join("..", "..", "docs")

	raw, err := os.ReadFile(filepath.Join(docsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var manifest struct {
		Groups []struct {
			ID string `json:"id"`
		} `json:"groups"`
		Docs []struct {
			Slug  string `json:"slug"`
			Group string `json:"group"`
		} `json:"docs"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse manifest.json: %v", err)
	}

	groupIDs := map[string]bool{}
	for _, g := range manifest.Groups {
		groupIDs[g.ID] = true
	}

	manifestSlugs := map[string]bool{}
	for _, d := range manifest.Docs {
		if manifestSlugs[d.Slug] {
			t.Errorf("manifest.json lists slug %q more than once", d.Slug)
		}
		manifestSlugs[d.Slug] = true
		if !groupIDs[d.Group] {
			t.Errorf("manifest doc %q references unknown group %q", d.Slug, d.Group)
		}
	}

	entries, err := os.ReadDir(docsDir)
	if err != nil {
		t.Fatalf("read docs dir: %v", err)
	}
	docSlugs := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".md") {
			continue
		}
		if strings.EqualFold(name, "README.md") {
			continue
		}
		slug := strings.ReplaceAll(strings.TrimSuffix(strings.ToLower(name), ".md"), "_", "-")
		docSlugs[slug] = true
	}

	for _, slug := range sortedKeys(docSlugs) {
		if !manifestSlugs[slug] {
			t.Errorf("doc %q has no entry in docs/manifest.json", slug)
		}
	}
	for _, slug := range sortedKeys(manifestSlugs) {
		if !docSlugs[slug] {
			t.Errorf("manifest entry %q has no corresponding docs/%s.md", slug, strings.ToUpper(strings.ReplaceAll(slug, "-", "_")))
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
