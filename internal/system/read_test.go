package system

import (
	"bytes"
	"errors"
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
