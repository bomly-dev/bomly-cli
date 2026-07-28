package git

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestCloneIntoRedactsUserinfoAndPreservesExitError(t *testing.T) {
	requireGit(t)
	const source = "unsupported://user:clone-secret@example.test/repository"
	err := cloneInto(context.Background(), nil, source, filepath.Join(t.TempDir(), "clone"), "", false, true)
	if err == nil {
		t.Fatal("cloneInto() error = nil, want unsupported transport error")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("cloneInto() did not preserve exec.ExitError: %v", err)
	}
	if strings.Contains(err.Error(), "user") || strings.Contains(err.Error(), "clone-secret") {
		t.Fatalf("cloneInto() exposed URL user information: %v", err)
	}
}

func TestCloneTempMaterializesRequestedCommitWithoutChangingSource(t *testing.T) {
	sourceRepo, mainSHA, featureSHA := createGitRepoWithFeatureBranch(t)

	materialized, err := CloneTemp(context.Background(), nil, sourceRepo, featureSHA)
	if err != nil {
		t.Fatalf("CloneTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(materialized) })

	if got := runGitCommand(t, materialized, "rev-parse", "HEAD"); got != featureSHA {
		t.Fatalf("materialized HEAD = %q, want %q", got, featureSHA)
	}
	if _, err := os.Stat(filepath.Join(materialized, "feature.txt")); err != nil {
		t.Fatalf("materialized feature file: %v", err)
	}
	if got := runGitCommand(t, sourceRepo, "rev-parse", "HEAD"); got != mainSHA {
		t.Fatalf("source HEAD changed to %q, want %q", got, mainSHA)
	}
}

func TestCloneTempCancellationRemovesPartialTarget(t *testing.T) {
	requireGit(t)
	sourceRepo, _, _ := createGitRepoWithFeatureBranch(t)
	tempRoot := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := cloneTemp(ctx, nil, sourceRepo, "", tempRoot); !errors.Is(err, context.Canceled) {
		t.Fatalf("cloneTemp() error = %v, want context cancellation", err)
	}
	entries, err := os.ReadDir(tempRoot)
	if err != nil {
		t.Fatalf("read temp root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("cloneTemp() left partial directories: %v", entries)
	}
}

func TestMaterializeLocalRefKeepsRepositorySymlinksAsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	requireGit(t)

	repoDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "target.txt")
	writePlatformTestFile(t, outside, "target\n")
	runGitCommand(t, repoDir, "init", "--initial-branch=main")
	runGitCommand(t, repoDir, "config", "user.email", "test@example.com")
	runGitCommand(t, repoDir, "config", "user.name", "Bomly Test")
	if err := os.Symlink(outside, filepath.Join(repoDir, "linked.txt")); err != nil {
		t.Fatalf("create repository symlink: %v", err)
	}
	runGitCommand(t, repoDir, "add", "linked.txt")
	runGitCommand(t, repoDir, "commit", "-m", "add symlink")

	materialized, err := MaterializeLocalRef(context.Background(), nil, repoDir, "HEAD")
	if err != nil {
		t.Fatalf("MaterializeLocalRef() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(materialized) })

	info, err := os.Lstat(filepath.Join(materialized, "linked.txt"))
	if err != nil {
		t.Fatalf("inspect materialized symlink: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("materialized link mode = %v, want symlink", info.Mode())
	}
}

func TestMaterializeRemoteRefRejectsEscapingRepositorySymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	requireGit(t)

	repoDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "package.json")
	writePlatformTestFile(t, outside, "{}")
	runGitCommand(t, repoDir, "init", "--initial-branch=main")
	runGitCommand(t, repoDir, "config", "user.email", "test@example.com")
	runGitCommand(t, repoDir, "config", "user.name", "Bomly Test")
	if err := os.Symlink(outside, filepath.Join(repoDir, "package.json")); err != nil {
		t.Fatalf("create repository symlink: %v", err)
	}
	runGitCommand(t, repoDir, "add", "package.json")
	runGitCommand(t, repoDir, "commit", "-m", "add escaping manifest")

	_, err := MaterializeRemoteRef(context.Background(), nil, repoDir, "HEAD")
	if err == nil {
		t.Fatal("MaterializeRemoteRef() error = nil, want containment error")
	}
	if !strings.Contains(err.Error(), `repository symlink "package.json" points outside`) {
		t.Fatalf("MaterializeRemoteRef() error = %v", err)
	}
	if strings.Contains(err.Error(), outside) {
		t.Fatalf("MaterializeRemoteRef() exposed outside path: %v", err)
	}
}

func TestMaterializationGitArgumentsDisableSubmoduleRecursion(t *testing.T) {
	got := materializationGitArgs([]string{"checkout", "--detach", "abc123"})
	want := []string{"-c", "submodule.recurse=false", "checkout", "--detach", "abc123"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("materializationGitArgs() = %#v, want %#v", got, want)
	}
}

func TestMaterializationGitEnvironmentDisablesLFSSmudge(t *testing.T) {
	got := materializationGitEnvironment([]string{
		"PATH=/usr/bin",
		"GIT_LFS_SKIP_SMUDGE=0",
		"OTHER=value",
	})
	if strings.Join(got, "\x00") != strings.Join([]string{
		"PATH=/usr/bin",
		"OTHER=value",
		"GIT_LFS_SKIP_SMUDGE=1",
	}, "\x00") {
		t.Fatalf("materializationGitEnvironment() = %#v", got)
	}
}

func TestValidateMaterializedTreeAllowsContainedSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(root, "data", "package.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("create target directory: %v", err)
	}
	writePlatformTestFile(t, target, "{}")
	if err := os.Symlink(filepath.Join("data", "package.json"), filepath.Join(root, "package.json")); err != nil {
		t.Fatalf("create contained symlink: %v", err)
	}

	if err := validateMaterializedTree(root, defaultMaterializedTreeLimits); err != nil {
		t.Fatalf("validateMaterializedTree() error = %v", err)
	}
}

func TestValidateMaterializedTreeRejectsEscapingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "package.json")
	writePlatformTestFile(t, outside, "{}")
	if err := os.Symlink(outside, filepath.Join(root, "package.json")); err != nil {
		t.Fatalf("create escaping symlink: %v", err)
	}

	err := validateMaterializedTree(root, defaultMaterializedTreeLimits)
	if err == nil {
		t.Fatal("validateMaterializedTree() error = nil, want containment error")
	}
	if !strings.Contains(err.Error(), `repository symlink "package.json" points outside the materialized target`) {
		t.Fatalf("validateMaterializedTree() error = %v", err)
	}
	if strings.Contains(err.Error(), outside) {
		t.Fatalf("validateMaterializedTree() exposed outside path: %v", err)
	}
}

func TestValidateMaterializedTreeRejectsLexicalEscapeFromBrokenSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	root := t.TempDir()
	if err := os.Symlink(filepath.Join("..", "missing", "package.json"), filepath.Join(root, "package.json")); err != nil {
		t.Fatalf("create broken escaping symlink: %v", err)
	}

	if err := validateMaterializedTree(root, defaultMaterializedTreeLimits); err == nil {
		t.Fatal("validateMaterializedTree() error = nil, want containment error")
	}
}

func TestValidateMaterializedTreeResourceBoundaries(t *testing.T) {
	t.Run("exact bytes and entries", func(t *testing.T) {
		root := t.TempDir()
		writePlatformTestFile(t, filepath.Join(root, "a.txt"), "1234")
		writePlatformTestFile(t, filepath.Join(root, "b.txt"), "5678")
		limits := materializedTreeLimits{maxEntries: 2, maxBytes: 8, maxDepth: 1}
		if err := validateMaterializedTree(root, limits); err != nil {
			t.Fatalf("validateMaterializedTree() error = %v", err)
		}
	})

	t.Run("one byte over", func(t *testing.T) {
		root := t.TempDir()
		writePlatformTestFile(t, filepath.Join(root, "data.txt"), "12345")
		limits := materializedTreeLimits{maxEntries: 1, maxBytes: 4, maxDepth: 1}
		err := validateMaterializedTree(root, limits)
		if err == nil || !strings.Contains(err.Error(), "exceeds 4 bytes") {
			t.Fatalf("validateMaterializedTree() error = %v, want byte limit", err)
		}
	})

	t.Run("one entry over", func(t *testing.T) {
		root := t.TempDir()
		writePlatformTestFile(t, filepath.Join(root, "a.txt"), "a")
		writePlatformTestFile(t, filepath.Join(root, "b.txt"), "b")
		limits := materializedTreeLimits{maxEntries: 1, maxBytes: 2, maxDepth: 1}
		err := validateMaterializedTree(root, limits)
		if err == nil || !strings.Contains(err.Error(), "exceeds 1 entries") {
			t.Fatalf("validateMaterializedTree() error = %v, want entry limit", err)
		}
	})

	t.Run("one level over", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "one", "two")
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("create nested path: %v", err)
		}
		limits := materializedTreeLimits{maxEntries: 2, maxBytes: 1, maxDepth: 1}
		err := validateMaterializedTree(root, limits)
		if err == nil || !strings.Contains(err.Error(), "exceeds maximum depth 1") {
			t.Fatalf("validateMaterializedTree() error = %v, want depth limit", err)
		}
	})
}

func TestRunGitContextHonorsCancellation(t *testing.T) {
	requireGit(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := runGitContext(ctx, nil, t.TempDir(), "status")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runGitContext() error = %v, want context cancellation", err)
	}
}

func TestResolveCommitWithSHA(t *testing.T) {
	repoDir, headSHA, _ := createGitRepoWithFeatureBranch(t)

	resolved, err := resolveCommit(nil, repoDir, headSHA)
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

	if err := VerifyRef(nil, cloneDir, "feature"); err != nil {
		t.Fatalf("VerifyRef() error = %v", err)
	}

	resolved, err := resolveCommit(nil, cloneDir, "feature")
	if err != nil {
		t.Fatalf("resolveCommit() error = %v", err)
	}
	if resolved != featureSHA {
		t.Fatalf("resolveCommit() = %q, want %q", resolved, featureSHA)
	}
}

func TestResolveCommitWithMissingRef(t *testing.T) {
	repoDir, _, _ := createGitRepoWithFeatureBranch(t)

	_, err := resolveCommit(nil, repoDir, "missing-branch")
	if err == nil {
		t.Fatal("resolveCommit() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "resolve git ref \"missing-branch\"") {
		t.Fatalf("resolveCommit() error = %v, want wrapped ref context", err)
	}
}

func TestRunGitLogsStderrAtDebug(t *testing.T) {
	requireGit(t)
	core, observed := observer.New(zap.DebugLevel)

	if _, err := runGit(zap.New(core), t.TempDir(), "rev-parse", "--verify", "missing-ref^{commit}"); err == nil {
		t.Fatal("runGit() error = nil, want error")
	}

	entries := observed.FilterMessage("Git command diagnostics").All()
	if len(entries) != 1 {
		t.Fatalf("Git diagnostic logs = %#v", observed.All())
	}
	if stderr, _ := entries[0].ContextMap()["stderr"].(string); !strings.Contains(stderr, "fatal:") {
		t.Fatalf("Git stderr log = %#v", entries[0].ContextMap())
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
