package attestation

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveFileSubject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	subject, err := ResolveSubject("file:"+path, SubjectOptions{})
	if err != nil {
		t.Fatalf("ResolveSubject() error = %v", err)
	}
	if subject.Kind != SubjectKindFile {
		t.Fatalf("Kind = %q, want file", subject.Kind)
	}
	if subject.Digest["sha256"] != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("unexpected digest: %#v", subject.Digest)
	}
}

func TestResolveDirSubjectIsDeterministicAndExcludesOutputs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "app"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for path, contents := range map[string]string{
		"package.json":     `{"name":"root"}`,
		"app/package.json": `{"name":"app"}`,
		".git/ignored":     "ignored",
		"sbom.spdx.json":   "output",
		"attestation.json": "output",
	} {
		fullPath := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(fullPath, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	opts := SubjectOptions{ExcludePaths: []string{filepath.Join(dir, "sbom.spdx.json"), filepath.Join(dir, "attestation.json")}}
	first, err := ResolveSubject("dir:"+dir, opts)
	if err != nil {
		t.Fatalf("ResolveSubject(first) error = %v", err)
	}
	second, err := ResolveSubject("dir:"+dir, opts)
	if err != nil {
		t.Fatalf("ResolveSubject(second) error = %v", err)
	}
	if first.Digest["sha256"] != second.Digest["sha256"] {
		t.Fatalf("digest not deterministic: %s != %s", first.Digest["sha256"], second.Digest["sha256"])
	}

	if err := os.WriteFile(filepath.Join(dir, "sbom.spdx.json"), []byte("changed"), 0o644); err != nil {
		t.Fatalf("rewrite excluded output: %v", err)
	}
	third, err := ResolveSubject("dir:"+dir, opts)
	if err != nil {
		t.Fatalf("ResolveSubject(third) error = %v", err)
	}
	if first.Digest["sha256"] != third.Digest["sha256"] {
		t.Fatalf("excluded output changed digest: %s != %s", first.Digest["sha256"], third.Digest["sha256"])
	}
}

func TestResolveContainerSubjectRequiresDigestRef(t *testing.T) {
	_, err := ResolveSubject("container:ghcr.io/acme/app:latest", SubjectOptions{})
	if err == nil || !strings.Contains(err.Error(), "requires image@sha256") {
		t.Fatalf("expected tag ref rejection, got %v", err)
	}

	digest := strings.Repeat("a", 64)
	subject, err := ResolveSubject("container:ghcr.io/acme/app@sha256:"+digest, SubjectOptions{})
	if err != nil {
		t.Fatalf("ResolveSubject(container digest) error = %v", err)
	}
	if subject.Kind != SubjectKindContainer || subject.Digest["sha256"] != digest {
		t.Fatalf("unexpected container subject: %#v", subject)
	}
}

func TestResolveGitSubjectRejectsDirtyTree(t *testing.T) {
	requireGitForAttestation(t)
	dir := t.TempDir()
	runGitForAttestation(t, dir, "init", "--initial-branch=main")
	runGitForAttestation(t, dir, "config", "user.email", "test@example.com")
	runGitForAttestation(t, dir, "config", "user.name", "Bomly Test")
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"demo"}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	runGitForAttestation(t, dir, "add", "package.json")
	runGitForAttestation(t, dir, "commit", "-m", "initial")
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"dirty"}`), 0o644); err != nil {
		t.Fatalf("dirty fixture: %v", err)
	}

	_, err := ResolveSubject("git", SubjectOptions{BaseDir: dir})
	if err == nil || !strings.Contains(err.Error(), "requires a clean worktree") {
		t.Fatalf("expected dirty tree rejection, got %v", err)
	}
}

func requireGitForAttestation(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "js" {
		t.Skip("git unavailable")
	}
	if _, err := os.Stat(".git"); err != nil {
		// This package can be tested outside a checkout; the git binary check
		// below still decides whether the actual git command can run.
	}
}

func runGitForAttestation(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return runCommandForAttestationTest(t, dir, "git", args...)
}
