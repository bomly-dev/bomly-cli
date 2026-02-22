package git

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly/bomly-cli/pkg/system"
	"go.uber.org/zap"
)

type executionLogger interface {
	Info(msg string, fields ...zap.Field)
	Debug(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
}

// CloneTemp clones repoURL into a temporary directory and optionally checks out ref.
// The caller owns cleanup of the returned directory.
func CloneTemp(logger executionLogger, repoURL, ref string) (string, error) {
	if err := ensureGitAvailable(); err != nil {
		return "", err
	}

	tempDir, err := os.MkdirTemp("", "bomly-git-*")
	if err != nil {
		return "", fmt.Errorf("create temp directory: %w", err)
	}
	if err := cloneInto(logger, repoURL, tempDir, ref, false); err != nil {
		_ = os.RemoveAll(tempDir)
		return "", err
	}
	return tempDir, nil
}

// FindRepoRoot resolves the git repository root for path.
func FindRepoRoot(path string) (string, error) {
	if err := ensureGitAvailable(); err != nil {
		return "", err
	}
	if path == "" {
		path = "."
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	stdout, err := run(absPath, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("find git repository root for %q: %w", absPath, err)
	}
	return strings.TrimSpace(stdout), nil
}

// VerifyRef verifies that ref resolves to a commit in repoPath.
func VerifyRef(repoPath, ref string) error {
	if ref == "" {
		return fmt.Errorf("ref is empty")
	}
	if _, err := resolveCommit(repoPath, ref); err != nil {
		return fmt.Errorf("verify git ref %q: %w", ref, err)
	}
	return nil
}

// CheckoutRef checks out ref in repoPath.
func CheckoutRef(logger executionLogger, repoPath, ref string) error {
	if ref == "" {
		return fmt.Errorf("ref is empty")
	}
	commit, err := resolveCommit(repoPath, ref)
	if err != nil {
		return err
	}
	return checkoutCommit(logger, repoPath, commit, ref)
}

// ResolveHEAD returns the current HEAD commit SHA for repoPath.
func ResolveHEAD(repoPath string) (string, error) {
	stdout, err := run(repoPath, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("resolve git HEAD: %w", err)
	}
	return strings.TrimSpace(stdout), nil
}

// MaterializeLocalRef clones sourceRepoPath into a temporary directory and checks out ref.
// The caller owns cleanup of the returned directory.
func MaterializeLocalRef(logger executionLogger, sourceRepoPath, ref string) (string, error) {
	if err := ensureGitAvailable(); err != nil {
		return "", err
	}
	root, err := FindRepoRoot(sourceRepoPath)
	if err != nil {
		return "", err
	}
	resolvedRef := ""
	if ref != "" {
		resolvedRef, err = resolveCommit(root, ref)
		if err != nil {
			return "", err
		}
	}
	tempDir, err := os.MkdirTemp("", "bomly-git-ref-*")
	if err != nil {
		return "", fmt.Errorf("create temp directory: %w", err)
	}
	if err := cloneInto(logger, root, tempDir, "", true); err != nil {
		_ = os.RemoveAll(tempDir)
		return "", err
	}
	if resolvedRef != "" {
		if err := checkoutCommit(logger, tempDir, resolvedRef, ref); err != nil {
			_ = os.RemoveAll(tempDir)
			return "", err
		}
	}
	return tempDir, nil
}

func ensureGitAvailable() error {
	if _, err := system.LookPath("git"); err != nil {
		return fmt.Errorf("locate git binary: %w", err)
	}
	return nil
}

func cloneInto(logger executionLogger, source, dest, ref string, local bool) error {
	args := []string{"clone", "--quiet"}
	if local {
		args = append(args, "--local")
	}
	args = append(args, source, dest)
	if _, err := run("", args...); err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Git clone failed: %v", err))
			logger.Debug("git clone failure details", zap.String("source", source), zap.String("destination", dest), zap.Error(err))
		}
		return fmt.Errorf("clone git repository %q: %w", source, err)
	}
	if ref != "" {
		if err := CheckoutRef(logger, dest, ref); err != nil {
			return err
		}
	}
	return nil
}

func resolveCommit(repoPath, ref string) (string, error) {
	for _, candidate := range refResolutionCandidates(ref) {
		stdout, err := run(repoPath, "rev-parse", "--verify", candidate+"^{commit}")
		if err == nil {
			return strings.TrimSpace(stdout), nil
		}
	}
	return "", fmt.Errorf("resolve git ref %q: not found", ref)
}

func refResolutionCandidates(ref string) []string {
	candidates := []string{ref}
	if strings.HasPrefix(ref, "refs/") || strings.HasPrefix(ref, "origin/") {
		return candidates
	}
	return append(candidates, "origin/"+ref)
}

func checkoutCommit(logger executionLogger, repoPath, commit, originalRef string) error {
	if _, err := run(repoPath, "checkout", "--quiet", "--detach", commit); err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Git checkout failed: %v", err))
			logger.Debug("git checkout failure details", zap.String("repository", repoPath), zap.String("ref", originalRef), zap.String("commit", commit), zap.Error(err))
		}
		return fmt.Errorf("checkout git ref %q: %w", originalRef, err)
	}
	return nil
}

func run(workingDir string, args ...string) (string, error) {
	cmd := system.Command("git", args...)
	if workingDir != "" {
		cmd.Dir = workingDir
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, message)
	}
	return stdout.String(), nil
}
