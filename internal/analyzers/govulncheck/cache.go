package govulncheck

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	cachepkg "github.com/bomly-dev/bomly-cli/internal/matchers/cache"
)

// cacheSchemaVersion bumps whenever the on-disk cache layout changes in a
// way that would silently produce wrong results. Bumping invalidates every
// previously cached entry.
const cacheSchemaVersion = "v1"

// defaultCacheTTL is the per-module result lifetime. govulncheck output
// changes when the vuln database updates, so we don't keep entries for
// long; 24h matches the OSV / EOL matcher TTLs and is a reasonable
// trade-off between hit rate and freshness.
const defaultCacheTTL = 24 * time.Hour

// resultCache wraps cachepkg.FileCache with the govulncheck-specific
// key construction and value type.
//
// A nil resultCache is a valid no-op that always reports cache miss; this
// keeps the analyzer working on systems where the cache directory cannot
// be created (read-only filesystems, sandboxes) without falling out of
// the happy path.
type resultCache struct {
	store *cachepkg.FileCache
}

// cachedRunnerResult is the JSON-serializable form of RunnerResult.
// RunnerResult.ImportedModules is a set; we serialize it as a sorted
// slice and rebuild the map on read.
type cachedRunnerResult struct {
	Findings        map[string]Finding `json:"findings,omitempty"`
	ImportedModules []string           `json:"imported_modules,omitempty"`
}

// newResultCache constructs a result cache rooted at dir. If dir is
// empty, the OS user cache directory is used. Errors creating the cache
// directory are non-fatal — they return a nil resultCache that the caller
// can use without checks.
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

// defaultCacheRoot returns the platform-appropriate cache directory for
// govulncheck analyzer results, or "" if the user cache directory cannot
// be determined.
func defaultCacheRoot() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, "bomly", "analyzers", "govulncheck")
}

// keyFor builds a stable cache key for one module run. The key folds
// every input that materially changes the runner output: the module
// directory, a content hash of go.sum (or go.mod when go.sum is absent),
// the Go runtime version, the runner name (builtin vs external), and the
// analyzer's cache schema version.
func keyFor(moduleDir, runnerName string) (cachepkg.Key, error) {
	checksum, err := moduleChecksum(moduleDir)
	if err != nil {
		return cachepkg.Key{}, err
	}
	parts := fmt.Sprintf("govulncheck|%s|%s|%s|%s|%s",
		cacheSchemaVersion, runnerName, runtime.Version(), moduleDir, checksum)
	return cachepkg.NewKey(parts, "govulncheck", "go", cacheSchemaVersion), nil
}

// moduleChecksum returns a short hex digest of the module's lockfile
// equivalent. It prefers go.sum (true lockfile) and falls back to go.mod
// when go.sum doesn't exist.
func moduleChecksum(moduleDir string) (string, error) {
	for _, name := range []string{"go.sum", "go.mod"} {
		path := filepath.Join(moduleDir, name)
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
	return "", fmt.Errorf("module %q has neither go.sum nor go.mod", moduleDir)
}

// get returns the cached RunnerResult for moduleDir and runnerName, or
// (zero value, false) on cache miss / cache failure. The boolean signals
// freshness only; callers that get false should run the analyzer.
func (c *resultCache) get(moduleDir, runnerName string) (RunnerResult, bool) {
	if c == nil {
		return RunnerResult{}, false
	}
	key, err := keyFor(moduleDir, runnerName)
	if err != nil {
		return RunnerResult{}, false
	}
	cached, ok := cachepkg.Get[cachedRunnerResult](c.store, key)
	if !ok {
		return RunnerResult{}, false
	}
	imported := make(map[string]struct{}, len(cached.ImportedModules))
	for _, m := range cached.ImportedModules {
		imported[m] = struct{}{}
	}
	return RunnerResult{Findings: cached.Findings, ImportedModules: imported}, true
}

// set writes the runner result to the cache. A non-nil error is
// non-fatal; callers should log it at debug level and continue.
func (c *resultCache) set(moduleDir, runnerName string, result RunnerResult) error {
	if c == nil {
		return nil
	}
	key, err := keyFor(moduleDir, runnerName)
	if err != nil {
		return err
	}
	imported := make([]string, 0, len(result.ImportedModules))
	for m := range result.ImportedModules {
		imported = append(imported, m)
	}
	cached := cachedRunnerResult{
		Findings:        result.Findings,
		ImportedModules: imported,
	}
	return cachepkg.Set(c.store, key, cached)
}
