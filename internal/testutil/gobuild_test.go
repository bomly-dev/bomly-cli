package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBuildGoBinary(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "hello")
	if runtime.GOOS == "windows" {
		outputPath += ".exe"
	}

	err := BuildGoBinary(t, outputPath, "package main\nfunc main() {}\n")
	if err != nil {
		t.Fatalf("BuildGoBinary() error = %v", err)
	}
	if _, statErr := os.Stat(outputPath); statErr != nil {
		t.Fatalf("expected built binary at %s: %v", outputPath, statErr)
	}
}
