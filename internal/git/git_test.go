package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveCommitWithSHA(t *testing.T) {
	repoDir, headSHA, _ := createGitRepoWithFeatureBranch(t)

	resolved, err := resolveCommit(repoDir, headSHA)
	if err != nil {
		t.Fatalf("resolveCommit() error = %v", err)
	}
	if resolved != headSHA {
		t.Fatalf("resolveCommit() = %q, want %q", resolved, headSHA)
	}
}

func TestResolveCommitWithRemoteTrackingBranch(t *testing.T) {
	sourceRepo, _, featureSHA := createGitRepoWithFeatureBranch(t)
	cloneDir := filepath.Join(t.TempDir(), "clone")
	runGitCommand(t, "", "clone", "--quiet", sourceRepo, cloneDir)

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

func TestResolveCommitWithMissingRef(t *testing.T) {
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
	runGitCommand(t, repoDir, "init", "--initial-branch=main")
	runGitCommand(t, repoDir, "config", "user.email", "test@example.com")
	runGitCommand(t, repoDir, "config", "user.name", "Bomly Test")

	writePlatformTestFile(t, filepath.Join(repoDir, "README.md"), "base\n")
	runGitCommand(t, repoDir, "add", "README.md")
	runGitCommand(t, repoDir, "commit", "-m", "base")
	headSHA := runGitCommand(t, repoDir, "rev-parse", "HEAD")

	runGitCommand(t, repoDir, "checkout", "-b", "feature")
	writePlatformTestFile(t, filepath.Join(repoDir, "feature.txt"), "feature branch\n")
	runGitCommand(t, repoDir, "add", "feature.txt")
	runGitCommand(t, repoDir, "commit", "-m", "feature")
	featureSHA := runGitCommand(t, repoDir, "rev-parse", "HEAD")
	runGitCommand(t, repoDir, "checkout", "main")

	return repoDir, headSHA, featureSHA
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git is required for this test: %v", err)
	}
}

func runGitCommand(t *testing.T, dir string, args ...string) string {
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

func writePlatformTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
