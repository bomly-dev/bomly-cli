// Package cache provides shared on-disk caching helpers for auditor packages.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Key uniquely identifies one cached auditor result.
type Key struct {
	raw string
}

// NewKey creates a stable cache key from the given fields.
// Callers should pass the most specific identity available.
func NewKey(purl, name, ecosystem, version string) Key {
	raw := fmt.Sprintf("%s|%s|%s|%s", purl, name, ecosystem, version)
	sum := sha256.Sum256([]byte(raw))
	return Key{raw: hex.EncodeToString(sum[:])}
}

// FileCache stores JSON-encoded values on disk with a TTL.
type FileCache struct {
	dir string
	ttl time.Duration
}

type entry[T any] struct {
	CachedAt time.Time `json:"cached_at"`
	Value    T         `json:"value"`
}

// NewFileCache creates a cache rooted at dir with the specified TTL.
func NewFileCache(dir string, ttl time.Duration) (*FileCache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &FileCache{dir: dir, ttl: ttl}, nil
}

func (c *FileCache) path(key Key) string {
	return filepath.Join(c.dir, key.raw+".json")
}

// Get returns the cached value for key if it exists and has not expired.
func Get[T any](c *FileCache, key Key) (T, bool) {
	var zero T
	data, err := os.ReadFile(c.path(key))
	if err != nil {
		return zero, false
	}
	var cached entry[T]
	if err := json.Unmarshal(data, &cached); err != nil {
		return zero, false
	}
	if time.Since(cached.CachedAt) > c.ttl {
		return zero, false
	}
	return cached.Value, true
}

// Set writes value to the cache under key.
func Set[T any](c *FileCache, key Key, value T) error {
	cached := entry[T]{CachedAt: time.Now(), Value: value}
	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}
	return os.WriteFile(c.path(key), data, 0o600)
}
