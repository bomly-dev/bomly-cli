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
				Description:   "Scans a pinned example project and compares the result with a recorded one.",
				EvidenceLevel: EvidencePinnedInput, CheckID: "smoke",
				Inputs: []Input{{
					Kind: "git", Location: "https://example.test/repo",
					Revision: "0f2103c7e671653e519cf5edb0d3e86020202ecf",
				}},
				Reproduce: [][]string{{"make", "smoke"}},
				Artifacts: []EvidenceArtifact{{
					Path: "go.mod", SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
				}},
				Proves:      []string{"It resolves."},
				Limitations: []string{"One toolchain."},
			}},
		}
	}
	if _, err := ParseCatalog(mustJSON(t, base())); err != nil {
		t.Fatalf("valid catalog rejected: %v", err)
	}

	cases := map[string]func(*Catalog){
		"bad schema":           func(c *Catalog) { c.SchemaVersion = "other/v1" },
		"no areas":             func(c *Catalog) { c.Areas = nil },
		"unknown check area":   func(c *Catalog) { c.Checks[0].Area = "nowhere" },
		"bad stage":            func(c *Catalog) { c.Checks[0].Stage = "later" },
		"bad level":            func(c *Catalog) { c.Checks[0].Level = "blocking" },
		"no source":            func(c *Catalog) { c.Checks[0].Source = Source{} },
		"blank claim":          func(c *Catalog) { c.Checks[0].Proves = []string{" "} },
		"no limitations":       func(c *Catalog) { c.Checks[0].Limitations = nil },
		"unknown backing":      func(c *Catalog) { c.Evidence[0].CheckID = "nothing" },
		"evidence description": func(c *Catalog) { c.Evidence[0].Description = " " },
		"undeclared instance":  func(c *Catalog) { c.Evidence[0].Instance = "go" },
		"bad evidence level":   func(c *Catalog) { c.Evidence[0].EvidenceLevel = "vibes" },
		"no inputs":            func(c *Catalog) { c.Evidence[0].Inputs = nil },
		"git without revision": func(c *Catalog) {
			c.Evidence[0].Inputs = []Input{{Kind: "git", Location: "https://example.test/repo"}}
		},
		"unsupported input kind": func(c *Catalog) {
			c.Evidence[0].Inputs = []Input{{Kind: "workflow", Location: ".github/workflows/smoke.yml"}}
		},
		"evidence without an artifact": func(c *Catalog) { c.Evidence[0].Artifacts = nil },
		"fixture without hash": func(c *Catalog) {
			c.Evidence[0].Inputs = []Input{{Kind: "fixture", Location: "go.mod"}}
		},
		"escaping fixture path": func(c *Catalog) {
			c.Evidence[0].Inputs = []Input{{
				Kind: "fixture", Location: "../../../etc/passwd",
				SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
			}}
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

// TestRepositoryCatalogProducesACompleteReport feeds the catalog a synthetic
// passing result for every check and instance it declares. It guards the wiring
// between the two: an evidence claim pointing at an instance no check can ever
// report, or a check whose instances cannot all be satisfied, shows up here
// instead of as a permanently "missing" entry in a published release report.
func TestRepositoryCatalogProducesACompleteReport(t *testing.T) {
	catalog := repositoryCatalog(t)
	var results []CheckResult
	for _, check := range catalog.Checks {
		instances := []string{""}
		if len(check.ExpectedInstances) > 0 {
			instances = nil
			for _, instance := range check.ExpectedInstances {
				instances = append(instances, instance.Name)
			}
		}
		for _, instance := range instances {
			results = append(results, CheckResult{
				SchemaVersion: CheckSchema, ID: check.ID, Instance: instance,
				Stage: check.Stage, Level: check.Level, Status: StatusPass,
				Summary: "Synthetic passing result.",
			})
		}
	}
	report := BuildReport(catalog, results, BuildOptions{
		Release:         Release{Tag: "v0.0.0", Version: "0.0.0"},
		IncludeEvidence: true,
	})
	if report.Verdict.Overall != StatusPass {
		t.Fatalf("verdict = %s, want pass; missing=%v gates=%v",
			report.Verdict.Overall, report.Verdict.MissingChecks, report.Verdict.GatesFailed)
	}
	if len(report.Unknown) != 0 {
		t.Fatalf("unknown results = %+v", report.Unknown)
	}
	if len(report.Checks) != len(catalog.Checks) {
		t.Fatalf("reported %d checks, catalog declares %d", len(report.Checks), len(catalog.Checks))
	}
	if len(report.Evidence) != len(catalog.Evidence) {
		t.Fatalf("reported %d evidence claims, catalog declares %d", len(report.Evidence), len(catalog.Evidence))
	}
	for _, evidence := range report.Evidence {
		if evidence.Status != StatusPass {
			t.Errorf("evidence %q resolved to %s even though every check passed", evidence.ID, evidence.Status)
		}
	}
	for _, stage := range Stages() {
		var found bool
		for _, reported := range report.Stages {
			if reported.ID == stage {
				found = true
				if reported.Verdict.Checks == 0 {
					t.Errorf("stage %s reported no checks", stage)
				}
			}
		}
		if !found {
			t.Errorf("stage %s is missing from the report", stage)
		}
	}
	if len(report.Coverage.Ecosystems) == 0 {
		t.Fatal("the coverage matrix is empty")
	}
}

func TestRefreshArtifactsRewritesDriftedHashes(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "golden.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	catalog := Catalog{Evidence: []Evidence{{
		ID: "example",
		Artifacts: []EvidenceArtifact{{
			Path: "golden.json", SHA256: "1111111111111111111111111111111111111111111111111111111111111111",
		}},
		Inputs: []Input{{
			Kind: "fixture", Location: "golden.json",
			SHA256: "2222222222222222222222222222222222222222222222222222222222222222",
		}},
	}}}
	changed, err := catalog.RefreshArtifacts(root)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if changed != 2 {
		t.Fatalf("refreshed %d hashes, want 2", changed)
	}
	if err := catalog.VerifyArtifacts(root); err != nil {
		t.Fatalf("refreshed catalog still fails verification: %v", err)
	}
	again, err := catalog.RefreshArtifacts(root)
	if err != nil || again != 0 {
		t.Fatalf("second refresh changed %d hashes (err=%v), want 0", again, err)
	}
}
