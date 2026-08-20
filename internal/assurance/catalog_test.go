package assurance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// repositoryRoot is the module root relative to this package.
const repositoryRoot = "../.."

func repositoryCatalog(t *testing.T) Catalog {
	t.Helper()
	catalog, err := LoadCatalog(filepath.Join(repositoryRoot, filepath.FromSlash(DefaultCatalogPath)))
	if err != nil {
		t.Fatalf("load repository catalog: %v", err)
	}
	return catalog
}

func TestRepositoryCatalogIsValid(t *testing.T) {
	catalog := repositoryCatalog(t)
	if err := catalog.VerifyArtifacts(repositoryRoot); err != nil {
		t.Fatalf("catalog artifacts drifted: %v", err)
	}
	for _, stage := range Stages() {
		if len(catalog.ChecksForStage(stage)) == 0 {
			t.Fatalf("no checks declared for the %s stage", stage)
		}
	}
	gates := 0
	for _, check := range catalog.Checks {
		if check.Level == LevelGate {
			gates++
		}
	}
	if gates == 0 {
		t.Fatal("the catalog declares no gate checks, so nothing could block a release")
	}
}

// TestCatalogSmokeInstancesMatchWorkflowMatrix keeps the declared smoke slices
// and the workflow matrix in step: a slice added to one and not the other would
// otherwise silently drop out of the report.
func TestCatalogSmokeInstancesMatchWorkflowMatrix(t *testing.T) {
	catalog := repositoryCatalog(t)
	check, found := catalog.Check("smoke")
	if !found {
		t.Fatal("the catalog does not declare the smoke check")
	}
	declared := map[string]struct{}{}
	for _, instance := range check.ExpectedInstances {
		declared[instance.Name] = struct{}{}
	}

	data, err := os.ReadFile(filepath.Join(repositoryRoot, ".github", "workflows", "smoke.yml"))
	if err != nil {
		t.Fatalf("read smoke workflow: %v", err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Slice []struct {
						Name string `yaml:"name"`
					} `yaml:"slice"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("decode smoke workflow: %v", err)
	}
	slices := workflow.Jobs["smoke"].Strategy.Matrix.Slice
	if len(slices) == 0 {
		t.Fatal("the smoke workflow declares no slices")
	}
	seen := map[string]struct{}{}
	for _, slice := range slices {
		seen[slice.Name] = struct{}{}
		if _, ok := declared[slice.Name]; !ok {
			t.Errorf("smoke slice %q runs in CI but is not declared in %s", slice.Name, DefaultCatalogPath)
		}
	}
	for name := range declared {
		if _, ok := seen[name]; !ok {
			t.Errorf("smoke slice %q is declared in the catalog but not in the workflow matrix", name)
		}
	}
}

func TestCatalogRejectsInvalidDocuments(t *testing.T) {
	base := func() Catalog {
		return Catalog{
			SchemaVersion: CatalogSchema,
			Areas:         []Area{{ID: "end-to-end", Title: "End to end", Description: "Real runs."}},
			Checks: []Check{{
				ID: "smoke", Title: "Smoke", Area: "end-to-end", Stage: StagePrerequisites,
				Level: LevelGate, Description: "Runs real scans.",
				Source: Source{Workflow: "smoke.yml", Job: "smoke"},
				Proves: []string{"It scans."}, Limitations: []string{"One project per ecosystem."},
			}},
			Evidence: []Evidence{{
				ID: "graph-go", Title: "Go graph", Area: "end-to-end",
				EvidenceLevel: EvidenceReleaseArtifact, CheckID: "smoke",
				Inputs:      []Input{{Kind: "release", Location: "https://example.test/release"}},
				Reproduce:   [][]string{{"make", "smoke"}},
				Proves:      []string{"It resolves."},
				Limitations: []string{"One toolchain."},
			}},
		}
	}
	if _, err := ParseCatalog(mustJSON(t, base())); err != nil {
		t.Fatalf("valid catalog rejected: %v", err)
	}

	cases := map[string]func(*Catalog){
		"bad schema":          func(c *Catalog) { c.SchemaVersion = "other/v1" },
		"no areas":            func(c *Catalog) { c.Areas = nil },
		"unknown check area":  func(c *Catalog) { c.Checks[0].Area = "nowhere" },
		"bad stage":           func(c *Catalog) { c.Checks[0].Stage = "later" },
		"bad level":           func(c *Catalog) { c.Checks[0].Level = "blocking" },
		"no source":           func(c *Catalog) { c.Checks[0].Source = Source{} },
		"blank claim":         func(c *Catalog) { c.Checks[0].Proves = []string{" "} },
		"no limitations":      func(c *Catalog) { c.Checks[0].Limitations = nil },
		"unknown backing":     func(c *Catalog) { c.Evidence[0].CheckID = "nothing" },
		"undeclared instance": func(c *Catalog) { c.Evidence[0].Instance = "go" },
		"bad evidence level":  func(c *Catalog) { c.Evidence[0].EvidenceLevel = "vibes" },
		"no inputs":           func(c *Catalog) { c.Evidence[0].Inputs = nil },
		"git without revision": func(c *Catalog) {
			c.Evidence[0].Inputs = []Input{{Kind: "git", Location: "https://example.test/repo"}}
		},
		"fixture without hash": func(c *Catalog) {
			c.Evidence[0].Inputs = []Input{{Kind: "fixture", Location: "go.mod"}}
		},
		"escaping fixture path": func(c *Catalog) {
			c.Evidence[0].Inputs = []Input{{
				Kind: "fixture", Location: "../../../etc/passwd",
				SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
			}}
		},
		"deterministic evidence needs an artifact": func(c *Catalog) {
			c.Evidence[0].EvidenceLevel = EvidenceDeterministic
		},
		"unsorted checks": func(c *Catalog) {
			c.Checks = append(c.Checks, c.Checks[0])
			c.Checks[1].ID = "aaa"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			catalog := base()
			mutate(&catalog)
			if _, err := ParseCatalog(mustJSON(t, catalog)); err == nil {
				t.Fatal("expected the catalog to be rejected")
			}
		})
	}
}

func TestVerifyArtifactsDetectsDrift(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "golden.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	catalog := Catalog{Evidence: []Evidence{{
		ID: "example",
		Artifacts: []EvidenceArtifact{{
			Path: "golden.json", SHA256: "1111111111111111111111111111111111111111111111111111111111111111",
		}},
	}}}
	if err := catalog.VerifyArtifacts(root); err == nil {
		t.Fatal("expected a hash mismatch to be reported")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
