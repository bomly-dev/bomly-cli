package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFileWithLimitAcceptsExactBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.json")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	data, err := readFileWithLimit(path, "test metadata", 4)
	if err != nil {
		t.Fatalf("readFileWithLimit() error = %v", err)
	}
	if string(data) != "1234" {
		t.Fatalf("data = %q, want exact boundary content", data)
	}
}

func TestReadFileWithLimitRejectsOverBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	_, err := readFileWithLimit(path, "test metadata", 4)
	if err == nil || !strings.Contains(err.Error(), "test metadata exceeds the 4-byte limit") {
		t.Fatalf("readFileWithLimit() error = %v", err)
	}
}

func TestPluginJSONReadersRejectOversizedFiles(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		limit       int64
		description string
		read        func(string) error
	}{
		{
			name:        "manifest",
			filename:    "bomly-plugin.json",
			limit:       maxPluginManifestBytes,
			description: "plugin manifest exceeds the 1 MiB limit",
			read: func(dir string) error {
				_, err := readManifest(dir)
				return err
			},
		},
		{
			name:        "runtime snapshot",
			filename:    "bomly-plugin.runtime.json",
			limit:       maxPluginRuntimeSnapshotBytes,
			description: "plugin runtime descriptor snapshot exceeds the 1 MiB limit",
			read: func(dir string) error {
				_, err := readRuntimeSnapshot(dir)
				return err
			},
		},
		{
			name:        "installed database",
			filename:    "installed.json",
			limit:       maxInstalledPluginDBBytes,
			description: "installed plugin database exceeds the 16 MiB limit",
			read: func(dir string) error {
				_, err := loadInstalledDB(dir)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.filename)
			file, err := os.Create(path)
			if err != nil {
				t.Fatalf("create oversized metadata: %v", err)
			}
			if err := file.Truncate(tt.limit + 1); err != nil {
				_ = file.Close()
				t.Fatalf("size oversized metadata: %v", err)
			}
			if err := file.Close(); err != nil {
				t.Fatalf("close oversized metadata: %v", err)
			}

			err = tt.read(dir)
			if err == nil || !strings.Contains(err.Error(), tt.description) {
				t.Fatalf("read oversized metadata error = %v, want %q", err, tt.description)
			}
		})
	}
}
