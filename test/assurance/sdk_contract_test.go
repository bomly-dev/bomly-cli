package assurance

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-sdk/filecache"
	"github.com/bomly-dev/bomly-sdk/logkit"
	"github.com/bomly-dev/bomly-sdk/system"
)

// These tests pin the security-relevant behavior of the bomly-sdk helper
// subpackages that Bomly's assurance docs rely on. The authoritative,
// exhaustive suites live upstream in the bomly-dev/bomly-sdk repository
// (system/read_test.go, logkit/command_test.go, logkit/stderr_test.go,
// filecache/cache_test.go); `make test` here does not execute a dependency's
// tests, so these thin contract checks re-assert the guarantees against the
// PINNED SDK version. They are deliberately small: each verifies that the
// documented boundary still holds, not the upstream implementation details.

func TestSDKContractReadLimitEnforcesBoundsAndGrowth(t *testing.T) {
	t.Parallel()

	// Exact limit is accepted.
	data, err := system.ReadLimit(strings.NewReader("12345678"), 8, 8)
	if err != nil || string(data) != "12345678" {
		t.Fatalf("ReadLimit(exact) = (%q, %v), want full content", data, err)
	}

	// A declared size over the limit fails before reading.
	if _, err := system.ReadLimit(strings.NewReader("123456789"), 9, 8); !errors.Is(err, system.ErrInputTooLarge) {
		t.Fatalf("ReadLimit(declared over) error = %v, want ErrInputTooLarge", err)
	}

	// A reader that streams more than its declared size (growth while
	// streaming) is rejected rather than truncated.
	if _, err := system.ReadLimit(strings.NewReader("123456789"), 4, 8); !errors.Is(err, system.ErrInputTooLarge) {
		t.Fatalf("ReadLimit(streamed growth) error = %v, want ErrInputTooLarge", err)
	}

	// Undeclared size (-1) still enforces the byte limit.
	if _, err := system.ReadLimit(strings.NewReader("123456789"), -1, 8); !errors.Is(err, system.ErrInputTooLarge) {
		t.Fatalf("ReadLimit(undeclared over) error = %v, want ErrInputTooLarge", err)
	}
}

func TestSDKContractReadRepositoryFileEnforces64MiBBound(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "oversized.bin")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Sparse-grow the file one byte past the shared repository limit; the
	// bound is checked against file size before content is read, so this
	// stays cheap.
	if err := os.Truncate(path, system.MaxRepositoryFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := system.ReadRepositoryFile(path); !errors.Is(err, system.ErrInputTooLarge) {
		t.Fatalf("ReadRepositoryFile(oversized) error = %v, want ErrInputTooLarge", err)
	}
}

func TestSDKContractSanitizeArgsRedactsCredentials(t *testing.T) {
	t.Parallel()

	got := logkit.SanitizeArgs([]string{
		"install",
		"--token", "plain-token",
		"--password=plain-password",
		"-Drepo.password=maven-password",
		"--registry=https://user:registry-password@example.test/packages",
		"//registry.npmjs.org/:_authToken=npm-secret",
		"--header", "Authorization: Bearer header-secret",
		"--color=always",
		"package-name",
	})
	joined := strings.Join(got, " ")
	for _, secret := range []string{
		"plain-token", "plain-password", "maven-password",
		"registry-password", "npm-secret", "header-secret",
	} {
		if strings.Contains(joined, secret) {
			t.Fatalf("SanitizeArgs() retained secret %q in %q", secret, joined)
		}
	}
	// Reproducibility survives: non-secret arguments stay intact.
	for _, keep := range []string{"install", "--token", "--color=always", "package-name"} {
		if !strings.Contains(joined, keep) {
			t.Fatalf("SanitizeArgs() dropped reproducible argument %q from %q", keep, joined)
		}
	}
}

func TestSDKContractCommandStderrHiddenBelowDebug(t *testing.T) {
	t.Parallel()

	var visible bytes.Buffer

	hidden := logkit.NewCommandStderr(&visible, false)
	if _, err := io.WriteString(hidden, "secret tool stderr\n"); err != nil {
		t.Fatal(err)
	}
	if visible.Len() != 0 {
		t.Fatalf("non-debug CommandStderr mirrored output: %q", visible.String())
	}
	if hidden.ByteCount() != int64(len("secret tool stderr\n")) {
		t.Fatalf("CommandStderr byte count = %d", hidden.ByteCount())
	}

	debug := logkit.NewCommandStderr(&visible, true)
	if _, err := io.WriteString(debug, "debug stderr\n"); err != nil {
		t.Fatal(err)
	}
	if visible.String() != "debug stderr\n" {
		t.Fatalf("debug CommandStderr did not mirror output, got %q", visible.String())
	}
}

func TestSDKContractFileCachePermissionsAndContainment(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	dir := filepath.Join(parent, "cache")
	fc, err := filecache.NewFileCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("cache dir permissions = %o, want 700", perm)
	}

	// Hostile identity text is hashed before it becomes a filename, so it
	// cannot escape the cache directory or inject path separators.
	hostile := filecache.NewKey("../../escape", "..", "../", "..\\..")
	if err := filecache.Set(fc, hostile, "value"); err != nil {
		t.Fatalf("Set(hostile key) error = %v", err)
	}
	if v, ok := filecache.Get[string](fc, hostile); !ok || v != "value" {
		t.Fatalf("Get(hostile key) = (%q, %v), want cached value", v, ok)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one cache entry inside the cache dir, got %d", len(entries))
	}
	name := entries[0].Name()
	if strings.ContainsAny(strings.TrimSuffix(name, ".json"), "./\\") {
		t.Fatalf("cache filename %q is not a pure hash", name)
	}
	entryInfo, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if perm := entryInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("cache entry permissions = %o, want 600", perm)
	}

	// Nothing escaped next to the cache directory.
	parentEntries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(parentEntries) != 1 || parentEntries[0].Name() != "cache" {
		t.Fatalf("cache write escaped its directory: %v", parentEntries)
	}

	// A corrupt entry degrades to a miss instead of an error.
	if err := os.WriteFile(filepath.Join(dir, name), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := filecache.Get[string](fc, hostile); ok {
		t.Fatal("corrupt cache entry should be a miss")
	}

	// An oversized entry (sparse-grown past the cache read bound) also
	// degrades to a miss instead of loading unbounded data.
	if err := os.Truncate(filepath.Join(dir, name), system.MaxRepositoryFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, ok := filecache.Get[string](fc, hostile); ok {
		t.Fatal("oversized cache entry should be a miss")
	}
}
