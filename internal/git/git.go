package git

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/system"
	"go.uber.org/zap"
)

// LineRange is an inclusive 1-based line range in a repository file.
type LineRange struct {
	Start int
	End   int
}

var diffHunkHeader = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// CloneTemp clones repoURL into a temporary directory and optionally checks out ref.
// The caller owns cleanup of the returned directory.
func CloneTemp(logger *zap.Logger, repoURL, ref string) (string, error) {
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
	stdout, err := runGit(absPath, "rev-parse", "--show-toplevel")
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

// ChangedLineRanges returns added/changed head-side line ranges from a git
// diff. Deleted-only hunks are omitted because there is no head line for SARIF
// to annotate.
func ChangedLineRanges(repoPath, baseRef, headRef string) (map[string][]LineRange, error) {
	if err := ensureGitAvailable(); err != nil {
		return nil, err
	}
	out, err := runGit(repoPath, "diff", "--unified=0", "--no-ext-diff", "--no-color", baseRef, headRef)
	if err != nil {
		return nil, fmt.Errorf("git diff %q..%q: %w", baseRef, headRef, err)
	}
	return parseChangedLineRanges(out), nil
}

// CheckoutRef checks out ref in repoPath.
func CheckoutRef(logger *zap.Logger, repoPath, ref string) error {
	if ref == "" {
		return fmt.Errorf("ref is empty")
	}
	commit, err := resolveCommit(repoPath, ref)
	if err != nil {
		return err
	}
	return checkoutCommit(logger, repoPath, commit, ref)
}

// MaterializeLocalRef clones sourceRepoPath into a temporary directory and checks out ref.
// The caller owns cleanup of the returned directory.
func MaterializeLocalRef(logger *zap.Logger, sourceRepoPath, ref string) (string, error) {
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

func cloneInto(logger *zap.Logger, source, dest, ref string, local bool) error {
	args := []string{"clone", "--quiet"}
	if local {
		args = append(args, "--local")
	}
	args = append(args, source, dest)
	if _, err := runGit("", args...); err != nil {
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
		stdout, err := runGit(repoPath, "rev-parse", "--verify", candidate+"^{commit}")
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

func checkoutCommit(logger *zap.Logger, repoPath, commit, originalRef string) error {
	if _, err := runGit(repoPath, "checkout", "--quiet", "--detach", commit); err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Git checkout failed: %v", err))
			logger.Debug("git checkout failure details", zap.String("repository", repoPath), zap.String("ref", originalRef), zap.String("commit", commit), zap.Error(err))
		}
		return fmt.Errorf("checkout git ref %q: %w", originalRef, err)
	}
	return nil
}

func runGit(workingDir string, args ...string) (string, error) {
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

func parseChangedLineRanges(diff string) map[string][]LineRange {
	ranges := make(map[string][]LineRange)
	currentFile := ""
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			path := strings.TrimSpace(strings.TrimPrefix(line, "+++ "))
			currentFile = normalizeDiffPath(path)
		case strings.HasPrefix(line, "@@ "):
			if currentFile == "" || currentFile == "/dev/null" {
				continue
			}
			matches := diffHunkHeader.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			start, err := strconv.Atoi(matches[1])
			if err != nil {
				continue
			}
			count := 1
			if matches[2] != "" {
				parsed, err := strconv.Atoi(matches[2])
				if err != nil {
					continue
				}
				count = parsed
			}
			if count <= 0 {
				continue
			}
			ranges[currentFile] = append(ranges[currentFile], LineRange{Start: start, End: start + count - 1})
		}
	}
	return ranges
}

func normalizeDiffPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "a/")
	path = strings.TrimPrefix(path, "b/")
	return filepath.ToSlash(path)
}
