package system

import (
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
	if _, err := ReadFileLimit(path, 3); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("over-limit error = %v, want ErrFileTooLarge", err)
	}
}
