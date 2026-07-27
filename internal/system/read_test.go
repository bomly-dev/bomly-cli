package system

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := ReadFileLimit(path, 4)
	if err != nil || string(data) != "1234" {
		t.Fatalf("exact-limit read = %q, %v", data, err)
	}
	if _, err := ReadFileLimit(path, 3); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("over-limit error = %v, want ErrInputTooLarge", err)
	}
	if _, err := ReadFileLimit(filepath.Join(t.TempDir(), "absent"), 4); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing-file error = %v, want os.ErrNotExist", err)
	}
}

func TestRepositoryAndCacheFileLimits(t *testing.T) {
	if MaxRepositoryFileBytes != 64<<20 {
		t.Fatalf("MaxRepositoryFileBytes = %d, want 64 MiB", MaxRepositoryFileBytes)
	}
	if MaxCacheEntryBytes != 64<<20 {
		t.Fatalf("MaxCacheEntryBytes = %d, want 64 MiB", MaxCacheEntryBytes)
	}
}

func TestReadLimitAcceptsExactLimitAndRejectsDeclaredOrStreamedExcess(t *testing.T) {
	data, err := ReadLimit(bytes.NewBufferString("1234"), -1, 4)
	if err != nil || string(data) != "1234" {
		t.Fatalf("exact-limit read = %q, %v", data, err)
	}
	if _, err := ReadLimit(bytes.NewBufferString("12345"), -1, 4); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("streamed over-limit error = %v, want ErrInputTooLarge", err)
	}
	if _, err := ReadLimit(bytes.NewBufferString(""), 5, 4); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("declared over-limit error = %v, want ErrInputTooLarge", err)
	}
}

func TestOpenFileLimitRejectsFileGrowthWhileStreaming(t *testing.T) {
	path := filepath.Join(t.TempDir(), "growing")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenFileLimit(path, 4)
	if err != nil {
		t.Fatalf("OpenFileLimit() error = %v", err)
	}
	defer func() { _ = reader.Close() }()
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("streamed growth error = %v, want ErrInputTooLarge", err)
	}
}

func TestByteLimitLabel(t *testing.T) {
	for size, want := range map[int64]string{
		4:       "4 bytes",
		4 << 10: "4 KiB",
		4 << 20: "4 MiB",
		4 << 30: "4 GiB",
	} {
		if got := ByteLimitLabel(size); got != want {
			t.Fatalf("ByteLimitLabel(%d) = %q, want %q", size, got, want)
		}
	}
}

func BenchmarkReadLimit(b *testing.B) {
	for _, size := range []int{1 << 10, 1 << 20, 8 << 20} {
		payload := bytes.Repeat([]byte("x"), size)
		b.Run(ByteLimitLabel(int64(size)), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				if _, err := ReadLimit(bytes.NewReader(payload), int64(size), int64(size)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
