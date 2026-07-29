package support

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs/faq.json is the source of truth for the landing page's /faq route. The
// site renders it with its own styled component and reuses the answer strings
// (backticks stripped) for FAQPage JSON-LD, so the data must stay well-formed
// here — a malformed entry should fail this repo's CI, not the site build.
func TestDocsFAQIsWellFormed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "faq.json"))
	if err != nil {
		t.Fatalf("read faq.json: %v", err)
	}

	var doc struct {
		Groups []struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			Icon      string `json:"icon"`
			Subgroups []struct {
				Label string `json:"label"`
				Faqs  []struct {
					ID       string `json:"id"`
					Question string `json:"question"`
					Toc      string `json:"toc"`
					Answer   string `json:"answer"`
					Links    []struct {
						Label    string `json:"label"`
						Href     string `json:"href"`
						External bool   `json:"external"`
					} `json:"links"`
				} `json:"faqs"`
			} `json:"subgroups"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse faq.json: %v", err)
	}
	if len(doc.Groups) == 0 {
		t.Fatal("faq.json has no groups")
	}

	groupIDs := map[string]bool{}
	faqIDs := map[string]bool{}
	for _, g := range doc.Groups {
		if g.ID == "" || g.Title == "" || g.Icon == "" {
			t.Errorf("group %q must have id, title, and icon", g.ID)
		}
		if groupIDs[g.ID] {
			t.Errorf("duplicate group id %q", g.ID)
		}
		groupIDs[g.ID] = true
		if len(g.Subgroups) == 0 {
			t.Errorf("group %q has no subgroups", g.ID)
		}
		for _, sg := range g.Subgroups {
			if len(sg.Faqs) == 0 {
				t.Errorf("group %q has a subgroup with no faqs", g.ID)
			}
			for _, f := range sg.Faqs {
				if f.ID == "" || f.Question == "" || f.Answer == "" {
					t.Errorf("faq %q in group %q must have id, question, and answer", f.ID, g.ID)
				}
				if faqIDs[f.ID] {
					t.Errorf("duplicate faq id %q", f.ID)
				}
				faqIDs[f.ID] = true
				// Question text becomes the JSON-LD Question name verbatim;
				// answers get backticks stripped, questions do not.
				if strings.Contains(f.Question, "`") {
					t.Errorf("faq %q question must not contain backticks", f.ID)
				}
				// Backtick code spans in answers must pair up for the site's
				// inline-code renderer.
				if strings.Count(f.Answer, "`")%2 != 0 {
					t.Errorf("faq %q answer has an unbalanced backtick", f.ID)
				}
				for _, l := range f.Links {
					if l.Label == "" || l.Href == "" {
						t.Errorf("faq %q has a link missing label or href", f.ID)
					}
					switch {
					case strings.HasPrefix(l.Href, "//"):
						// Protocol-relative URLs resolve to an external origin
						// but would pass the site-relative branch below.
						t.Errorf("faq %q link %q must not be protocol-relative", f.ID, l.Href)
					case strings.HasPrefix(l.Href, "/"):
						if l.External {
							t.Errorf("faq %q link %q is site-relative but marked external", f.ID, l.Href)
						}
					case strings.HasPrefix(l.Href, "https://"):
						if !l.External {
							t.Errorf("faq %q link %q is absolute but not marked external", f.ID, l.Href)
						}
					default:
						t.Errorf("faq %q link %q must start with / or https://", f.ID, l.Href)
					}
				}
			}
		}
	}
}
