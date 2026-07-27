package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileCache_RoundTrip(t *testing.T) {
	cache, err := NewFileCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewFileCache: %v", err)
	}

	key := NewKey("pkg:npm/lodash@4.17.15", "", "", "")
	type payload struct {
		Name string
	}
	want := payload{Name: "lodash"}

	if err := Set(cache, key, want); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, ok := Get[payload](cache, key)
	if !ok {
		t.Fatal("Get returned false (miss) after Set")
	}
	if got.Name != want.Name {
		t.Errorf("Get = %+v, want %+v", got, want)
	}
}

func TestFileCache_TTLExpiry(t *testing.T) {
	cache, err := NewFileCache(t.TempDir(), time.Nanosecond)
	if err != nil {
		t.Fatalf("NewFileCache: %v", err)
	}

	key := NewKey("pkg:npm/express@4.18.0", "", "", "")
	if err := Set(cache, key, "cached-value"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, ok := Get[string](cache, key)
	if ok {
		t.Error("expected cache miss after TTL expiry, got hit")
	}
}

func TestFileCache_InvalidJSON_GracefulMiss(t *testing.T) {
	cache, err := NewFileCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewFileCache: %v", err)
	}

	key := NewKey("pkg:npm/broken@1.0.0", "", "", "")
	if writeErr := os.WriteFile(cache.path(key), []byte("not-valid-json"), 0o600); writeErr != nil {
		t.Fatalf("WriteFile: %v", writeErr)
	}

	_, ok := Get[string](cache, key)
	if ok {
		t.Error("expected cache miss for invalid JSON, got hit")
	}
}

func TestFileCache_HostileIdentityCannotEscapeCacheDirectory(t *testing.T) {
	root := t.TempDir()
	cache, err := NewFileCache(root, time.Hour)
	if err != nil {
		t.Fatalf("NewFileCache: %v", err)
	}

	key := NewKey("../../outside", `..\outside`, "/absolute", "1.0.0")
	path := cache.path(key)
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("relative cache path: %v", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		t.Fatalf("cache path escaped root: root=%q path=%q rel=%q", root, path, rel)
	}
	if filepath.Ext(path) != ".json" {
		t.Fatalf("cache path = %q, want JSON extension", path)
	}
	if err := Set(cache, key, "safe"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "outside")); !os.IsNotExist(err) {
		t.Fatalf("hostile identity wrote outside cache: %v", err)
	}
}
