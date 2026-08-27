package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSPDXJarAcceptsOnlyPinnedRootEntry(t *testing.T) {
	archive := writeTestArchive(t, map[string]string{
		spdxJarName: "jar-content",
		"README.md": "metadata",
	})
	destination := t.TempDir()
	path, err := extractSPDXJar(archive, destination)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(destination, spdxJarName) {
		t.Fatalf("extracted path = %q", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "jar-content" {
		t.Fatalf("extracted content = %q", data)
	}
}

func TestExtractSPDXJarRejectsHostileAndUnexpectedEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries map[string]string
	}{
		{name: "parent traversal", entries: map[string]string{"../" + spdxJarName: "hostile"}},
		{name: "nested path", entries: map[string]string{"nested/" + spdxJarName: "hostile"}},
		{name: "absolute path", entries: map[string]string{"/" + spdxJarName: "hostile"}},
		{name: "wrong jar", entries: map[string]string{"other-jar-with-dependencies.jar": "wrong"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination := t.TempDir()
			_, err := extractSPDXJar(writeTestArchive(t, test.entries), destination)
			if err == nil || !strings.Contains(err.Error(), "does not contain root entry") {
				t.Fatalf("extractSPDXJar error = %v", err)
			}
			if entries, readErr := os.ReadDir(destination); readErr != nil || len(entries) != 0 {
				t.Fatalf("hostile archive wrote destination entries: entries=%v err=%v", entries, readErr)
			}
		})
	}
}

func writeTestArchive(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "validator.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, content := range entries {
		entry, createErr := writer.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := entry.Write([]byte(content)); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
