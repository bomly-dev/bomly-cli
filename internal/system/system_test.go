package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileExistsAndPathEnv(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "demo.txt")
	if err := os.WriteFile(file, []byte("demo"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	exists, err := FileExists(file)
	if err != nil || !exists {
		t.Fatalf("FileExists(file) = %t, %v", exists, err)
	}
	exists, err = FileExists(dir)
	if err != nil || exists {
		t.Fatalf("FileExists(dir) = %t, %v", exists, err)
	}

	if PathEnv() == "" {
		t.Fatal("expected PATH env to be populated")
	}
}

func TestAbsCommandAndDirectories(t *testing.T) {
	if _, err := Abs("."); err != nil {
		t.Fatalf("Abs() error = %v", err)
	}
	cmd := Command("go", "version")
	if cmd == nil || cmd.Path == "" && cmd.Args[0] != "go" {
		t.Fatalf("unexpected command %#v", cmd)
	}
	if _, err := Getwd(); err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if _, err := UserHomeDir(); err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}
	if _, err := LookPath("go"); err != nil {
		t.Fatalf("LookPath(go) error = %v", err)
	}
}
