package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveCommit_WithSHA(t *testing.T) {
	repoDir, headSHA, _ := createGitRepoWithFeatureBranch(t)

	resolved, err := resolveCommit(repoDir, headSHA)
	if err != nil {
		t.Fatalf("resolveCommit() error = %v", err)
	}
	if resolved != headSHA {
		t.Fatalf("resolveCommit() = %q, want %q", resolved, headSHA)
	}
}

func TestResolveCommit_WithRemoteTrackingBranch(t *testing.T) {
	sourceRepo, _, featureSHA := createGitRepoWithFeatureBranch(t)
	cloneDir := filepath.Join(t.TempDir(), "clone")
	runGit(t, "", "clone", "--quiet", sourceRepo, cloneDir)

	if err := VerifyRef(cloneDir, "feature"); err != nil {
		t.Fatalf("VerifyRef() error = %v", err)
	}

	resolved, err := resolveCommit(cloneDir, "feature")
	if err != nil {
		t.Fatalf("resolveCommit() error = %v", err)
	}
	if resolved != featureSHA {
		t.Fatalf("resolveCommit() = %q, want %q", resolved, featureSHA)
	}
}

func TestResolveCommit_WithMissingRef(t *testing.T) {
	repoDir, _, _ := createGitRepoWithFeatureBranch(t)

	_, err := resolveCommit(repoDir, "missing-branch")
	if err == nil {
		t.Fatal("resolveCommit() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "resolve git ref \"missing-branch\"") {
		t.Fatalf("resolveCommit() error = %v, want wrapped ref context", err)
	}
}

func createGitRepoWithFeatureBranch(t *testing.T) (string, string, string) {
	t.Helper()
	requireGit(t)

	repoDir := t.TempDir()
	runGit(t, repoDir, "init", "--initial-branch=main")
	runGit(t, repoDir, "config", "user.email", "test@example.com")
	runGit(t, repoDir, "config", "user.name", "Bomly Test")

	writeFile(t, filepath.Join(repoDir, "README.md"), "base\n")
	runGit(t, repoDir, "add", "README.md")
	runGit(t, repoDir, "commit", "-m", "base")
	headSHA := runGit(t, repoDir, "rev-parse", "HEAD")

	runGit(t, repoDir, "checkout", "-b", "feature")
	writeFile(t, filepath.Join(repoDir, "feature.txt"), "feature branch\n")
	runGit(t, repoDir, "add", "feature.txt")
	runGit(t, repoDir, "commit", "-m", "feature")
	featureSHA := runGit(t, repoDir, "rev-parse", "HEAD")
	runGit(t, repoDir, "checkout", "main")

	return repoDir, headSHA, featureSHA
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git is required for this test: %v", err)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
