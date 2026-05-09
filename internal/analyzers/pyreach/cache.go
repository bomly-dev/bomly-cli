package pyreach

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cachepkg "github.com/bomly-dev/bomly-cli/internal/matchers/cache"
)

// cacheSchemaVersion bumps whenever the on-disk cache layout changes
// in a way that would silently produce wrong results. Bumping
// invalidates every previously cached entry.
const cacheSchemaVersion = "v1"

// defaultCacheTTL matches the OSV / EOL / govulncheck / jsreach
// matchers. pyreach output changes whenever the project's lockfile
// or source tree changes; the lockfile hash in the key catches the
// lockfile case but not editor-time source edits, so we keep TTL
// short enough that stale entries don't survive long.
const defaultCacheTTL = 24 * time.Hour

// resultCache wraps cachepkg.FileCache with the pyreach-specific key
// construction and value type. A nil resultCache is a valid no-op
// that always reports cache miss.
type resultCache struct {
	store *cachepkg.FileCache
}

// cachedRunnerResult is the JSON-serializable form of RunnerResult.
type cachedRunnerResult struct {
	ImportedDistributions []string `json:"imported_distributions,omitempty"`
	SourceFiles           int      `json:"source_files,omitempty"`
	SkippedDirs           []string `json:"skipped_dirs,omitempty"`
}

// newResultCache constructs a result cache rooted at dir. If dir is
// empty, the OS user cache directory is used. Errors creating the
// cache directory are non-fatal — they return a nil resultCache that
// the caller can use without checks.
func newResultCache(dir string, ttl time.Duration) *resultCache {
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	root := dir
	if root == "" {
		root = defaultCacheRoot()
	}
	if root == "" {
		return nil
	}
	store, err := cachepkg.NewFileCache(root, ttl)
	if err != nil {
		return nil
	}
	return &resultCache{store: store}
}

// defaultCacheRoot returns the platform-appropriate cache directory
// for pyreach analyzer results, or "" if the user cache directory
// cannot be determined.
func defaultCacheRoot() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, "bomly", "analyzers", "pyreach")
}

// keyFor builds a stable cache key for one project pass. Folds every
// input that materially changes the runner output: the project
// directory, a content hash of the lockfile (or pyproject / setup.py
// when no lockfile is present), the runner name and version, and
// the analyzer's cache schema version.
func keyFor(projectDir, runnerName, runnerVersion string) (cachepkg.Key, error) {
	checksum, err := projectChecksum(projectDir)
	if err != nil {
		return cachepkg.Key{}, err
	}
	parts := fmt.Sprintf("pyreach|%s|%s|%s|%s|%s",
		cacheSchemaVersion, runnerName, runnerVersion, projectDir, checksum)
	return cachepkg.NewKey(parts, "pyreach", "python", cacheSchemaVersion), nil
}

// lockfileCandidates lists the files we hash to fingerprint the
// project, in priority order. The first one that exists wins. The
// list mirrors projectFileMarkers minus loose source files.
var lockfileCandidates = []string{
	"poetry.lock",
	"pdm.lock",
	"uv.lock",
	"Pipfile.lock",
	"requirements.txt",
	"requirements-dev.txt",
	"pyproject.toml",
	"Pipfile",
	"setup.py",
	"setup.cfg",
}

// projectChecksum returns a short hex digest of the project's
// lockfile equivalent. A change there means the dependency closure
// changed, so the import graph could change too. Source-only edits
// don't move the cache key — that's why TTL is 24h, not infinity.
func projectChecksum(projectDir string) (string, error) {
	for _, name := range lockfileCandidates {
		path := filepath.Join(projectDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:8]), nil
	}
	return "", fmt.Errorf("project %q has no recognised lockfile or manifest", projectDir)
}

// get returns the cached RunnerResult for projectDir + runner, or
// (zero value, false) on cache miss / cache failure.
func (c *resultCache) get(projectDir, runnerName, runnerVersion string) (RunnerResult, bool) {
	if c == nil {
		return RunnerResult{}, false
	}
	key, err := keyFor(projectDir, runnerName, runnerVersion)
	if err != nil {
		return RunnerResult{}, false
	}
	cached, ok := cachepkg.Get[cachedRunnerResult](c.store, key)
	if !ok {
		return RunnerResult{}, false
	}
	imports := make(map[string]struct{}, len(cached.ImportedDistributions))
	for _, m := range cached.ImportedDistributions {
		imports[m] = struct{}{}
	}
	return RunnerResult{
		ImportedDistributions: imports,
		SourceFiles:           cached.SourceFiles,
		SkippedDirs:           append([]string(nil), cached.SkippedDirs...),
	}, true
}

// set writes the runner result to the cache. A non-nil error is
// non-fatal; callers should log it at debug level and continue.
func (c *resultCache) set(projectDir, runnerName, runnerVersion string, result RunnerResult) error {
	if c == nil {
		return nil
	}
	key, err := keyFor(projectDir, runnerName, runnerVersion)
	if err != nil {
		return err
	}
	imports := make([]string, 0, len(result.ImportedDistributions))
	for m := range result.ImportedDistributions {
		imports = append(imports, m)
	}
	cached := cachedRunnerResult{
		ImportedDistributions: imports,
		SourceFiles:           result.SourceFiles,
		SkippedDirs:           append([]string(nil), result.SkippedDirs...),
	}
	return cachepkg.Set(c.store, key, cached)
}
