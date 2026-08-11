package plugin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateArchiveEntryName(t *testing.T) {
	valid := []string{
		"", ".", "bin/plugin", "bin/", "manifest.json", "nested/dir/file.txt", "dir/",
	}
	for _, name := range valid {
		if err := validateArchiveEntryName(name); err != nil {
			t.Errorf("validateArchiveEntryName(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{
		"../evil",
		"/absolute/evil",
		`\absolute\evil`,
		`..\evil`,
		"a/../../b",
		"safe/../../../escape",
		"..",
		"../",
		`C:\evil`,
		"C:/evil",
		"dir/../..",
	}
	for _, name := range invalid {
		if err := validateArchiveEntryName(name); err == nil {
			t.Errorf("validateArchiveEntryName(%q) = nil, want error", name)
		}
	}
}

func TestExtractZipArchiveRejectsEscapingAndSymlinkEntries(t *testing.T) {
	tests := []struct {
		name string
		path string
		mode os.FileMode
	}{
		{name: "parent traversal", path: "../escape"},
		{name: "absolute path", path: "/tmp/escape"},
		{name: "Windows traversal", path: `..\escape`},
		{name: "Windows absolute path", path: `C:\evil`},
		{name: "interior traversal", path: "a/../../b"},
		{name: "nested parent component", path: "safe/../../../escape"},
		{name: "symlink", path: "link", mode: os.ModeSymlink | 0o777},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "plugin.zip")
			file, err := os.Create(archivePath)
			if err != nil {
				t.Fatal(err)
			}
			writer := zip.NewWriter(file)
			header := &zip.FileHeader{Name: tc.path, Method: zip.Store}
			header.SetMode(tc.mode)
			entry, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write([]byte("content")); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}

			err = extractZipArchive(archivePath, t.TempDir(), defaultArchiveLimits())
			if err == nil {
				t.Fatalf("extractZipArchive() accepted unsafe entry %q", tc.path)
			}
			if !strings.Contains(err.Error(), "escapes the extraction directory") &&
				!strings.Contains(err.Error(), "uses an absolute path") &&
				!strings.Contains(err.Error(), "parent-directory component") &&
				!strings.Contains(err.Error(), "unsupported symlink mode") {
				t.Fatalf("extractZipArchive() error = %v", err)
			}
		})
	}
}

func TestExtractTarGzArchiveRejectsEscapingLinksAndSpecialFiles(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		typeflag byte
	}{
		{name: "parent traversal", path: "../escape", typeflag: tar.TypeReg},
		{name: "absolute path", path: "/tmp/escape", typeflag: tar.TypeReg},
		{name: "interior traversal", path: "a/../../b", typeflag: tar.TypeReg},
		{name: "Windows traversal", path: `..\escape`, typeflag: tar.TypeReg},
		{name: "symbolic link", path: "link", typeflag: tar.TypeSymlink},
		{name: "hard link", path: "hard-link", typeflag: tar.TypeLink},
		{name: "device", path: "device", typeflag: tar.TypeChar},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "plugin.tar.gz")
			var archive bytes.Buffer
			gzipWriter := gzip.NewWriter(&archive)
			tarWriter := tar.NewWriter(gzipWriter)
			header := &tar.Header{
				Name:     tc.path,
				Mode:     0o644,
				Size:     int64(len("content")),
				Typeflag: tc.typeflag,
			}
			if tc.typeflag != tar.TypeReg {
				header.Size = 0
			}
			if err := tarWriter.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if tc.typeflag == tar.TypeReg {
				if _, err := tarWriter.Write([]byte("content")); err != nil {
					t.Fatal(err)
				}
			}
			if err := tarWriter.Close(); err != nil {
				t.Fatal(err)
			}
			if err := gzipWriter.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(archivePath, archive.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}

			err := extractTarGzArchive(archivePath, t.TempDir(), defaultArchiveLimits())
			if err == nil {
				t.Fatalf("extractTarGzArchive() accepted unsafe entry %q", tc.path)
			}
			if !strings.Contains(err.Error(), "escapes the extraction directory") &&
				!strings.Contains(err.Error(), "uses an absolute path") &&
				!strings.Contains(err.Error(), "parent-directory component") &&
				!strings.Contains(err.Error(), "uses unsupported type") {
				t.Fatalf("extractTarGzArchive() error = %v", err)
			}
		})
	}
}

// TestExtractZipArchiveAcceptsDottedFilenames guards against over-broad
// traversal checks: ".." inside a filename is legitimate; only exact ".."
// path components, absolute paths, and drive paths are traversal.
func TestExtractZipArchiveAcceptsDottedFilenames(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "plugin.zip")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create("licenses/foo..bar.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("dotted")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	targetDir := t.TempDir()
	if err := extractZipArchive(archivePath, targetDir, defaultArchiveLimits()); err != nil {
		t.Fatalf("extractZipArchive() rejected a legitimate dotted filename: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(targetDir, "licenses", "foo..bar.txt"))
	if err != nil {
		t.Fatalf("read extracted dotted file: %v", err)
	}
	if string(content) != "dotted" {
		t.Fatalf("unexpected extracted content %q", content)
	}
}
