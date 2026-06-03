package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRoot_RegistersSBOMCommands(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}
	for _, args := range [][]string{{"sbom"}, {"sbom", "attest"}, {"sbom", "verify"}} {
		cmd, _, err := root.Find(args)
		if err != nil {
			t.Fatalf("root.Find(%v) error = %v", args, err)
		}
		if cmd == nil {
			t.Fatalf("expected command for %v", args)
		}
	}
}

func TestSBOMCommandHelpMarksAttestationExperimental(t *testing.T) {
	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stdout)
	root.SetArgs([]string{"sbom", "attest", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "Experimental") {
		t.Fatalf("expected experimental help text, got:\n%s", stdout.String())
	}
}

func TestSBOMAttestAndVerifyCommandsRoundTrip(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "bomly.spdx.json")
	if err := os.WriteFile(sbomPath, []byte(cliMinimalSPDXDocument()), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	subjectPath := filepath.Join(dir, "artifact.txt")
	if err := os.WriteFile(subjectPath, []byte("artifact"), 0o644); err != nil {
		t.Fatalf("write subject: %v", err)
	}
	bundlePath := filepath.Join(dir, "sbom.att.json")
	extractedPath := filepath.Join(dir, "verified.spdx.json")

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"sbom", "attest", "--sbom", sbomPath, "--subject", "file:" + subjectPath, "--output", bundlePath, "--keyless"})
	if err := root.Execute(); err != nil {
		t.Fatalf("attest error = %v; stderr=%s", err, stderr.String())
	}
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("expected bundle output: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	root, err = newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"sbom", "verify", "--attestation", bundlePath, "--subject", "file:" + subjectPath, "--extract-sbom", extractedPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("verify error = %v; stderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Verified SBOM attestation") {
		t.Fatalf("unexpected verify output: %s", stdout.String())
	}
	if _, err := os.Stat(extractedPath); err != nil {
		t.Fatalf("expected extracted sbom: %v", err)
	}
}

func cliMinimalSPDXDocument() string {
	return `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "demo",
  "documentNamespace": "https://bomly.dev/test/demo-cli",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Tool: bomly-test"]
  },
  "packages": []
}`
}
