package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"go.uber.org/zap"
)

// LineRange is an inclusive 1-based line range in a repository file.
type LineRange struct {
	Start int
	End   int
}

var diffHunkHeader = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

const (
	// RemoteOperationTimeout bounds one constrained remote materialization flow.
	// Git does not expose a reliable byte quota, so elapsed time is the
	// enforceable in-process boundary before checkout validation.
	RemoteOperationTimeout = 10 * time.Minute

	maxMaterializedEntries = 1_000_000
	maxMaterializedBytes   = int64(10 << 30)
	maxMaterializedDepth   = 256
)

type materializedTreeLimits struct {
	maxEntries int
	maxBytes   int64
	maxDepth   int
}

var defaultMaterializedTreeLimits = materializedTreeLimits{
	maxEntries: maxMaterializedEntries,
	maxBytes:   maxMaterializedBytes,
	maxDepth:   maxMaterializedDepth,
}

// CloneTemp clones repoURL into a temporary directory and optionally checks out ref.
// The caller owns cleanup of the returned directory.
func CloneTemp(ctx context.Context, logger *zap.Logger, repoURL, ref string) (string, error) {
	return cloneTemp(ctx, logger, repoURL, ref, "")
}

func cloneTemp(ctx context.Context, logger *zap.Logger, repoURL, ref, tempRoot string) (string, error) {
	if err := ensureGitAvailable(); err != nil {
		return "", err
	}

	operationCtx, cancel := context.WithTimeout(ctx, RemoteOperationTimeout)
	defer cancel()

	tempDir, err := os.MkdirTemp(tempRoot, "bomly-git-*")
	if err != nil {
		return "", fmt.Errorf("create temp directory: %w", err)
	}
	if err := cloneInto(operationCtx, logger, repoURL, tempDir, ref, false, true); err != nil {
		_ = os.RemoveAll(tempDir)
		return "", err
	}
	if err := validateMaterializedTree(tempDir, defaultMaterializedTreeLimits); err != nil {
		_ = os.RemoveAll(tempDir)
		return "", fmt.Errorf("validate cloned repository: %w", err)
	}
	return tempDir, nil
}

// FindRepoRoot resolves the git repository root for path.
func FindRepoRoot(logger *zap.Logger, path string) (string, error) {
	return findRepoRootWithRunner(context.Background(), logger, path, runGitContext)
}

func findRepoRootWithRunner(ctx context.Context, logger *zap.Logger, path string, runner gitContextRunner) (string, error) {
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
	stdout, err := runner(ctx, logger, absPath, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("find git repository root for %q: %w", absPath, err)
	}
	return strings.TrimSpace(stdout), nil
}

// VerifyRef verifies that ref resolves to a commit in repoPath.
func VerifyRef(logger *zap.Logger, repoPath, ref string) error {
	if ref == "" {
		return fmt.Errorf("ref is empty")
	}
	if _, err := resolveCommit(logger, repoPath, ref); err != nil {
		return fmt.Errorf("verify git ref %q: %w", ref, err)
	}
	return nil
}

// ChangedLineRanges returns added/changed head-side line ranges from a git
// diff. Deleted-only hunks are omitted because there is no head line for SARIF
// to annotate.
func ChangedLineRanges(logger *zap.Logger, repoPath, baseRef, headRef string) (map[string][]LineRange, error) {
	if err := ensureGitAvailable(); err != nil {
		return nil, err
	}
	out, err := runGit(logger, repoPath, "diff", "--unified=0", "--no-ext-diff", "--no-color", baseRef, headRef)
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
	commit, err := resolveCommit(logger, repoPath, ref)
	if err != nil {
		return err
	}
	return checkoutCommit(logger, repoPath, commit, ref)
}

// MaterializeLocalRef clones sourceRepoPath into a temporary directory and checks out ref.
// Local repositories are trusted inputs, so repository symlinks are preserved
// even when they point outside the checkout.
// The caller owns cleanup of the returned directory.
func MaterializeLocalRef(ctx context.Context, logger *zap.Logger, sourceRepoPath, ref string) (string, error) {
	return materializeRef(ctx, logger, sourceRepoPath, ref, false)
}

// MaterializeRemoteRef clones an already-fetched remote repository into a
// temporary directory, checks out ref, and validates the resulting tree.
// The caller owns cleanup of the returned directory.
func MaterializeRemoteRef(ctx context.Context, logger *zap.Logger, sourceRepoPath, ref string) (string, error) {
	operationCtx, cancel := context.WithTimeout(ctx, RemoteOperationTimeout)
	defer cancel()
	path, err := materializeRef(operationCtx, logger, sourceRepoPath, ref, true)
	if err != nil && errors.Is(err, context.DeadlineExceeded) {
		return "", fmt.Errorf("materialize remote git ref %q: timed out after %s: %w", ref, RemoteOperationTimeout, err)
	}
	return path, err
}

func materializeRef(ctx context.Context, logger *zap.Logger, sourceRepoPath, ref string, constrained bool) (string, error) {
	if err := ensureGitAvailable(); err != nil {
		return "", err
	}
	runner := runGitContext
	if constrained {
		runner = runMaterializationGitContext
	}
	root, err := findRepoRootWithRunner(ctx, logger, sourceRepoPath, runner)
	if err != nil {
		return "", err
	}
	resolvedRef := ""
	if ref != "" {
		resolvedRef, err = resolveCommitWithRunner(ctx, logger, root, ref, runner)
		if err != nil {
			return "", err
		}
	}
	tempDir, err := os.MkdirTemp("", "bomly-git-ref-*")
	if err != nil {
		return "", fmt.Errorf("create temp directory: %w", err)
	}
	if err := cloneInto(ctx, logger, root, tempDir, "", true, constrained); err != nil {
		_ = os.RemoveAll(tempDir)
		return "", err
	}
	if resolvedRef != "" {
		if err := checkoutCommitContext(ctx, logger, tempDir, resolvedRef, ref, constrained); err != nil {
			_ = os.RemoveAll(tempDir)
			return "", err
		}
	}
	if constrained {
		if err := validateMaterializedTree(tempDir, defaultMaterializedTreeLimits); err != nil {
			_ = os.RemoveAll(tempDir)
			return "", fmt.Errorf("validate materialized repository: %w", err)
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

func cloneInto(ctx context.Context, logger *zap.Logger, source, dest, ref string, local, constrained bool) error {
	safeSource := logging.SanitizeURL(source)
	args := make([]string, 0, 10)
	args = append(args, "clone", "--quiet", "--no-recurse-submodules")
	if local {
		args = append(args, "--local")
	}
	args = append(args, source, dest)
	runner := runGitContext
	if constrained {
		runner = runMaterializationGitContext
	}
	if _, err := runner(ctx, logger, "", args...); err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Git clone failed: %v", err))
			logger.Debug("git clone failure details", zap.String("source", safeSource), zap.String("destination", dest), zap.Error(err))
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("clone git repository %q: timed out after %s: %w", safeSource, RemoteOperationTimeout, err)
		}
		return fmt.Errorf("clone git repository %q: %w", safeSource, err)
	}
	if ref != "" {
		commit, err := resolveCommitWithRunner(ctx, logger, dest, ref, runner)
		if err != nil {
			return err
		}
		if err := checkoutCommitWithRunner(ctx, logger, dest, commit, ref, runner); err != nil {
			return err
		}
	}
	return nil
}

func resolveCommit(logger *zap.Logger, repoPath, ref string) (string, error) {
	return resolveCommitContext(context.Background(), logger, repoPath, ref)
}

func resolveCommitContext(ctx context.Context, logger *zap.Logger, repoPath, ref string) (string, error) {
	return resolveCommitWithRunner(ctx, logger, repoPath, ref, runGitContext)
}

type gitContextRunner func(context.Context, *zap.Logger, string, ...string) (string, error)

func resolveCommitWithRunner(ctx context.Context, logger *zap.Logger, repoPath, ref string, runner gitContextRunner) (string, error) {
	for _, candidate := range refResolutionCandidates(ref) {
		stdout, err := runner(ctx, logger, repoPath, "rev-parse", "--verify", candidate+"^{commit}")
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
	return checkoutCommitContext(context.Background(), logger, repoPath, commit, originalRef, false)
}

func checkoutCommitContext(ctx context.Context, logger *zap.Logger, repoPath, commit, originalRef string, constrained bool) error {
	runner := runGitContext
	if constrained {
		runner = runMaterializationGitContext
	}
	return checkoutCommitWithRunner(ctx, logger, repoPath, commit, originalRef, runner)
}

func checkoutCommitWithRunner(ctx context.Context, logger *zap.Logger, repoPath, commit, originalRef string, runner gitContextRunner) error {
	if _, err := runner(ctx, logger, repoPath, "checkout", "--quiet", "--detach", commit); err != nil {
		if logger != nil {
			logger.Error(fmt.Sprintf("Git checkout failed: %v", err))
			logger.Debug("git checkout failure details", zap.String("repository", repoPath), zap.String("ref", originalRef), zap.String("commit", commit), zap.Error(err))
		}
		return fmt.Errorf("checkout git ref %q: %w", originalRef, err)
	}
	return nil
}

func runGit(logger *zap.Logger, workingDir string, args ...string) (string, error) {
	return runGitContext(context.Background(), logger, workingDir, args...)
}

func runGitContext(ctx context.Context, logger *zap.Logger, workingDir string, args ...string) (string, error) {
	return runGitContextWithEnv(ctx, logger, workingDir, nil, args...)
}

func runMaterializationGitContext(ctx context.Context, logger *zap.Logger, workingDir string, args ...string) (string, error) {
	return runGitContextWithEnv(
		ctx,
		logger,
		workingDir,
		materializationGitEnvironment(os.Environ()),
		materializationGitArgs(args)...,
	)
}

func materializationGitArgs(args []string) []string {
	constrained := make([]string, 0, len(args)+2)
	constrained = append(constrained, "-c", "submodule.recurse=false")
	return append(constrained, args...)
}

func materializationGitEnvironment(environment []string) []string {
	const key = "GIT_LFS_SKIP_SMUDGE="
	constrained := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if strings.HasPrefix(entry, key) {
			continue
		}
		constrained = append(constrained, entry)
	}
	return append(constrained, key+"1")
}

func runGitContextWithEnv(ctx context.Context, logger *zap.Logger, workingDir string, environment []string, args ...string) (string, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	logger.Debug("running Git command", logging.CommandFields("git", args, workingDir)...)
	cmd := system.CommandContext(ctx, "git", args...)
	if workingDir != "" {
		cmd.Dir = workingDir
	}
	if environment != nil {
		cmd.Env = environment
	}
	var stdout bytes.Buffer
	var diagnostics bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &diagnostics
	err := cmd.Run()
	if message := strings.TrimSpace(diagnostics.String()); message != "" {
		logger.Debug("Git command diagnostics", zap.String("stderr", message))
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("%w (stderr bytes: %d)", ctxErr, diagnostics.Len())
		}
		return "", fmt.Errorf("%w (stderr bytes: %d)", err, diagnostics.Len())
	}
	return stdout.String(), nil
}

// validateMaterializedTree rejects links whose target escapes a temporary
// checkout. Links that remain within the checkout are preserved. The .git
// directory is excluded because detectors never treat repository metadata as
// project input.
func validateMaterializedTree(root string, limits materializedTreeLimits) error {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve checkout root: %w", err)
	}
	var entries int
	var regularBytes int64
	return filepath.WalkDir(absoluteRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("inspect checkout path: %w", walkErr)
		}
		if path == filepath.Join(absoluteRoot, ".git") && entry.IsDir() {
			return filepath.SkipDir
		}
		if path != absoluteRoot {
			entries++
			if entries > limits.maxEntries {
				return fmt.Errorf("materialized repository exceeds %d entries", limits.maxEntries)
			}
			rel := relativePath(absoluteRoot, path)
			if depth := pathDepth(rel); depth > limits.maxDepth {
				return fmt.Errorf("repository path %q exceeds maximum depth %d", rel, limits.maxDepth)
			}
		}
		if entry.Type()&os.ModeSymlink == 0 {
			if entry.Type().IsRegular() {
				info, err := entry.Info()
				if err != nil {
					return fmt.Errorf("inspect checkout file %q: %w", relativePath(absoluteRoot, path), err)
				}
				if info.Size() > limits.maxBytes-regularBytes {
					return fmt.Errorf("materialized repository exceeds %s of regular files", system.ByteLimitLabel(limits.maxBytes))
				}
				regularBytes += info.Size()
			}
			return nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			return fmt.Errorf("read repository symlink %q: %w", relativePath(absoluteRoot, path), err)
		}
		resolved := target
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(filepath.Dir(path), resolved)
		}
		resolved = filepath.Clean(resolved)
		rel, err := filepath.Rel(absoluteRoot, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("repository symlink %q points outside the materialized target", relativePath(absoluteRoot, path))
		}
		return nil
	})
}

func pathDepth(path string) int {
	if path == "" || path == "." {
		return 0
	}
	return strings.Count(filepath.ToSlash(path), "/") + 1
}

func relativePath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.ToSlash(rel)
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
