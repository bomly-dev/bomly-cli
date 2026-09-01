package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadAndValidateCatalog(t *testing.T) {
	root := t.TempDir()
	artifactPath := filepath.Join(root, "result.json")
	data := []byte(`{"ok":true}`)
	if err := os.WriteFile(artifactPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	catalogPath := filepath.Join(root, "cases.json")
	document := `{
  "schema_version": "bomly.public-evidence/v1",
  "cases": [{
    "id": "example-case",
    "title": "Example",
    "area": "graph",
    "evidence_level": "deterministic",
    "inputs": [{"kind": "fixture", "location": "result.json", "sha256": "` + hash + `"}],
    "reproduce": [["go", "test", "./..."]],
    "evidence": [{"path": "result.json", "sha256": "` + hash + `"}],
    "proves": ["The example succeeds."],
    "limitations": ["The example covers one input."]
  }]
}`
	if err := os.WriteFile(catalogPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadCatalog(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCatalog(root, loaded); err != nil {
		t.Fatal(err)
	}

	loaded.Cases[0].Proves = []string{" "}
	if err := validateCatalog(root, loaded); err == nil || !strings.Contains(err.Error(), "blank entries") {
		t.Fatalf("validateCatalog() blank proof error = %v", err)
	}
	loaded.Cases[0].Proves = []string{"The example succeeds."}
	loaded.Cases[0].Limitations = []string{"\t"}
	if err := validateCatalog(root, loaded); err == nil || !strings.Contains(err.Error(), "blank entries") {
		t.Fatalf("validateCatalog() blank limitation error = %v", err)
	}
}

func TestValidateCatalogRejectsUnpinnedGitAndChangedArtifact(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "result.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	current := catalog{
		SchemaVersion: catalogSchema,
		Cases: []evidenceCase{{
			Title:         "Git case",
			Area:          "graph",
			EvidenceLevel: "pinned-input",
			Inputs: []input{{
				Kind:     "git",
				Location: "https://github.com/example/project",
				Revision: "main",
			}},
			Reproduce:   [][]string{{"go", "test", "./..."}},
			Evidence:    []artifact{{Path: "result.json", SHA256: strings.Repeat("0", 64)}},
			Proves:      []string{"A result."},
			Limitations: []string{"One input."},
		}},
	}
	if err := validateCatalog(root, current); err == nil || !strings.Contains(err.Error(), "full lowercase commit") {
		t.Fatalf("validateCatalog() error = %v", err)
	}

	current.Cases[0].Inputs[0].Revision = strings.Repeat("a", 40)
	if err := validateCatalog(root, current); err == nil || !strings.Contains(err.Error(), "artifact") {
		t.Fatalf("validateCatalog() error = %v", err)
	}
}

func TestValidateCatalogRejectsUnsortedAndUnknownFields(t *testing.T) {
	root := t.TempDir()
	current := catalog{
		SchemaVersion: catalogSchema,
		Cases: []evidenceCase{
			{ID: "z-case"},
			{ID: "a-case"},
		},
	}
	if err := validateCatalog(root, current); err == nil || !strings.Contains(err.Error(), "not sorted") {
		t.Fatalf("validateCatalog() error = %v", err)
	}

	path := filepath.Join(root, "cases.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"bomly.public-evidence/v1","cases":[],"extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCatalog(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("loadCatalog() error = %v", err)
	}
}

func TestValidateInputRequiresDigestForPinnedContainer(t *testing.T) {
	tagged := input{Kind: "container", Location: "Docker Hub", Ref: "alpine:3.20"}
	if err := validateInput(t.TempDir(), "pinned-input", tagged); err == nil ||
		!strings.Contains(err.Error(), "immutable sha256 digest") {
		t.Fatalf("validateInput() tagged pinned container error = %v", err)
	}
	if err := validateInput(t.TempDir(), "snapshot", tagged); err != nil {
		t.Fatalf("validateInput() snapshot tag error = %v", err)
	}
	digested := tagged
	digested.Ref = "alpine@sha256:" + strings.Repeat("a", 64)
	if err := validateInput(t.TempDir(), "pinned-input", digested); err != nil {
		t.Fatalf("validateInput() digest error = %v", err)
	}
}

func TestValidateArtifactRejectsSymlinkOutsideRepository(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	root := t.TempDir()
	data := []byte("outside")
	outside := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(outside, data, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "result.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	err := validateArtifact(root, artifact{
		Path:   "result.json",
		SHA256: hex.EncodeToString(sum[:]),
	})
	if err == nil || !strings.Contains(err.Error(), "resolves outside the repository") {
		t.Fatalf("validateArtifact() error = %v", err)
	}
}

func TestResolveCatalogPathHonorsAbsolutePath(t *testing.T) {
	root := t.TempDir()
	absolute := filepath.Join(t.TempDir(), "cases.json")
	if got := resolveCatalogPath(root, absolute); got != absolute {
		t.Fatalf("resolveCatalogPath() absolute = %q, want %q", got, absolute)
	}
	wantRelative := filepath.Join(root, "test", "evidence", "cases.json")
	if got := resolveCatalogPath(root, "test/evidence/cases.json"); got != wantRelative {
		t.Fatalf("resolveCatalogPath() relative = %q, want %q", got, wantRelative)
	}
}

func TestShellCommandQuotesPatterns(t *testing.T) {
	got := shellCommand([]string{"go", "test", "-run", "TestScan$/scan-npm$"})
	want := "go test -run 'TestScan$/scan-npm$'"
	if got != want {
		t.Fatalf("shellCommand() = %q, want %q", got, want)
	}
}
