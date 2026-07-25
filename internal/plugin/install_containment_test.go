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

func TestExtractZipArchiveRejectsEscapingAndSymlinkEntries(t *testing.T) {
	tests := []struct {
		name string
		path string
		mode os.FileMode
	}{
		{name: "parent traversal", path: "../escape"},
		{name: "absolute path", path: "/tmp/escape"},
		{name: "Windows traversal", path: `..\escape`},
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

			err = extractZipArchive(archivePath, t.TempDir())
			if err == nil {
				t.Fatalf("extractZipArchive() accepted unsafe entry %q", tc.path)
			}
			if !strings.Contains(err.Error(), "escapes the extraction directory") &&
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

			err := extractTarGzArchive(archivePath, t.TempDir())
			if err == nil {
				t.Fatalf("extractTarGzArchive() accepted unsafe entry %q", tc.path)
			}
			if !strings.Contains(err.Error(), "escapes the extraction directory") &&
				!strings.Contains(err.Error(), "uses unsupported type") {
				t.Fatalf("extractTarGzArchive() error = %v", err)
			}
		})
	}
}
