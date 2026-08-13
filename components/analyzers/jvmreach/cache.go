package jvmreach

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cachepkg "github.com/bomly-dev/bomly-sdk/filecache"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/system"
)

const cacheSchemaVersion = "v3"
const defaultCacheTTL = 24 * time.Hour

type resultCache struct {
	store *cachepkg.FileCache
}

type cachedRunnerResult struct {
	ImportedArtifacts      []string `json:"imported_artifacts,omitempty"`
	RawImports             []string `json:"raw_imports,omitempty"`
	SourceFiles            int      `json:"source_files,omitempty"`
	SkippedDirs            []string `json:"skipped_dirs,omitempty"`
	DynamicImportsDetected bool     `json:"dynamic_imports_detected,omitempty"`
}

// newResultCache constructs a result cache rooted at dir. If dir is
// empty, the OS user cache directory is used. Errors creating the
// cache directory are non-fatal — they log one WARN and return a nil
// resultCache that the caller can use without checks.
func newResultCache(dir string, ttl time.Duration, logger *zap.Logger) *resultCache {
	logger = ensureLogger(logger)
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	root := dir
	if root == "" {
		defaultRoot, err := defaultCacheRoot()
		if err != nil {
			logger.Warn("jvmreach: result cache disabled: user cache directory unavailable (non-fatal)",
				zap.Error(err))
			return nil
		}
		root = defaultRoot
	}
	store, err := cachepkg.NewFileCache(root, ttl)
	if err != nil {
		logger.Warn("jvmreach: result cache disabled: cache initialization failed (non-fatal)",
			zap.String("dir", root), zap.Error(err))
		return nil
	}
	return &resultCache{store: store}
}

// defaultCacheRoot returns the platform-appropriate cache directory
// for jvmreach analyzer results, or an error when the user cache
// directory cannot be determined.
func defaultCacheRoot() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	if base == "" {
		return "", errors.New("user cache directory is empty")
	}
	return filepath.Join(base, "bomly", "analyzers", "jvmreach"), nil
}

func keyFor(projectDir, runnerName, runnerVersion string) (cachepkg.Key, error) {
	checksum, err := projectChecksum(projectDir)
	if err != nil {
		return cachepkg.Key{}, err
	}
	parts := fmt.Sprintf("jvmreach|%s|%s|%s|%s|%s",
		cacheSchemaVersion, runnerName, runnerVersion, projectDir, checksum)
	return cachepkg.NewKey(parts, "jvmreach", "maven", cacheSchemaVersion), nil
}

// lockfileCandidates lists the files hashed to fingerprint the
// project. The first one that exists wins. Gradle's `dependencies`
// task can produce a lockfile under `gradle/dependency-locks/` but
// it isn't required, so we fall back to the build script itself.
var lockfileCandidates = []string{
	"gradle.lockfile",
	"pom.xml",
	"build.gradle.kts",
	"build.gradle",
	"build.sbt",
	"settings.gradle.kts",
	"settings.gradle",
}

func projectChecksum(projectDir string) (string, error) {
	for _, name := range lockfileCandidates {
		path := filepath.Join(projectDir, name)
		data, err := system.ReadRepositoryFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:8]), nil
	}
	return "", fmt.Errorf("project %q has no recognised build manifest", projectDir)
}

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
	artifacts := make(map[string]struct{}, len(cached.ImportedArtifacts))
	for _, a := range cached.ImportedArtifacts {
		artifacts[a] = struct{}{}
	}
	rawImports := make(map[string]struct{}, len(cached.RawImports))
	for _, fqn := range cached.RawImports {
		rawImports[fqn] = struct{}{}
	}
	return RunnerResult{
		ImportedArtifacts:      artifacts,
		RawImports:             rawImports,
		SourceFiles:            cached.SourceFiles,
		SkippedDirs:            append([]string(nil), cached.SkippedDirs...),
		DynamicImportsDetected: cached.DynamicImportsDetected,
	}, true
}

func (c *resultCache) set(projectDir, runnerName, runnerVersion string, result RunnerResult) error {
	if c == nil {
		return nil
	}
	key, err := keyFor(projectDir, runnerName, runnerVersion)
	if err != nil {
		return err
	}
	artifacts := make([]string, 0, len(result.ImportedArtifacts))
	for a := range result.ImportedArtifacts {
		artifacts = append(artifacts, a)
	}
	rawImports := make([]string, 0, len(result.RawImports))
	for fqn := range result.RawImports {
		rawImports = append(rawImports, fqn)
	}
	cached := cachedRunnerResult{
		ImportedArtifacts:      artifacts,
		RawImports:             rawImports,
		SourceFiles:            result.SourceFiles,
		SkippedDirs:            append([]string(nil), result.SkippedDirs...),
		DynamicImportsDetected: result.DynamicImportsDetected,
	}
	return cachepkg.Set(c.store, key, cached)
}
