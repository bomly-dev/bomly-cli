package plugin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCopyDownloadWithLimit(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		contentLength int64
		limit         int64
		wantWritten   int64
		wantError     string
	}{
		{
			name:          "below limit",
			body:          "abc",
			contentLength: 3,
			limit:         4,
			wantWritten:   3,
		},
		{
			name:          "at limit",
			body:          "abcd",
			contentLength: 4,
			limit:         4,
			wantWritten:   4,
		},
		{
			name:          "declared length over limit",
			body:          "abcde",
			contentLength: 5,
			limit:         4,
			wantError:     "exceeds the 4-byte limit",
		},
		{
			name:          "streamed body over limit",
			body:          "abcde",
			contentLength: -1,
			limit:         4,
			wantWritten:   4,
			wantError:     "exceeds the 4-byte limit",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var destination bytes.Buffer
			written, err := copyDownloadWithLimit(&destination, strings.NewReader(tt.body), tt.contentLength, tt.limit)
			if written != tt.wantWritten {
				t.Fatalf("written = %d, want %d", written, tt.wantWritten)
			}
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("copyDownloadWithLimit() error = %v", err)
				}
				if destination.String() != tt.body {
					t.Fatalf("downloaded body = %q, want %q", destination.String(), tt.body)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("copyDownloadWithLimit() error = %v, want %q", err, tt.wantError)
			}
			if int64(destination.Len()) > tt.limit {
				t.Fatalf("downloaded %d bytes, limit is %d", destination.Len(), tt.limit)
			}
		})
	}
}

func TestInstallRemoteArchiveRejectsDeclaredDownloadOverLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(maxPluginDownloadBytes+1, 10))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root := t.TempDir()
	tempDir := filepath.Join(root, "install")
	if err := os.Mkdir(tempDir, 0o755); err != nil {
		t.Fatalf("create install directory: %v", err)
	}
	_, _, err := installRemoteArchive(t.Context(), tempDir, server.URL+"/plugin.zip", InstallOptions{
		InsecureSkipChecksum: true,
	})
	wantError := "exceeds the " + strconv.FormatInt(maxPluginDownloadBytes, 10) + "-byte limit"
	if err == nil || !strings.Contains(err.Error(), wantError) {
		t.Fatalf("installRemoteArchive() error = %v", err)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatalf("read temp parent: %v", readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "bomly-plugin-archive-") {
			t.Fatalf("oversized declared download created temporary archive %q", entry.Name())
		}
	}
}

func TestArchiveExtractionLimitsAtBoundary(t *testing.T) {
	entries := []testArchiveEntry{
		{name: "bin/plugin", body: "abc"},
		{name: "bomly-plugin.json", body: "de"},
	}
	limits := archiveLimits{maxEntries: 2, maxEntryBytes: 3, maxExpandedBytes: 5}

	for _, format := range []string{"zip", "tar.gz"} {
		t.Run(format, func(t *testing.T) {
			archivePath := writeLimitTestArchive(t, format, entries)
			targetDir := t.TempDir()
			if err := extractLimitTestArchive(format, archivePath, targetDir, limits); err != nil {
				t.Fatalf("extract archive at limits: %v", err)
			}
			for _, entry := range entries {
				data, err := os.ReadFile(filepath.Join(targetDir, filepath.FromSlash(entry.name)))
				if err != nil {
					t.Fatalf("read extracted entry %q: %v", entry.name, err)
				}
				if string(data) != entry.body {
					t.Fatalf("entry %q = %q, want %q", entry.name, data, entry.body)
				}
			}
		})
	}
}

func TestArchiveExtractionRejectsResourceLimits(t *testing.T) {
	tests := []struct {
		name      string
		entries   []testArchiveEntry
		limits    archiveLimits
		wantError string
	}{
		{
			name: "entry count",
			entries: []testArchiveEntry{
				{name: "one", body: "a"},
				{name: "two", body: "b"},
			},
			limits:    archiveLimits{maxEntries: 1, maxEntryBytes: 4, maxExpandedBytes: 8},
			wantError: "entries",
		},
		{
			name:      "single expanded entry",
			entries:   []testArchiveEntry{{name: "plugin", body: "abc"}},
			limits:    archiveLimits{maxEntries: 2, maxEntryBytes: 2, maxExpandedBytes: 8},
			wantError: "entry \"plugin\" exceeds the 2-byte expanded size limit",
		},
		{
			name: "total expanded bytes",
			entries: []testArchiveEntry{
				{name: "one", body: "ab"},
				{name: "two", body: "cde"},
			},
			limits:    archiveLimits{maxEntries: 2, maxEntryBytes: 3, maxExpandedBytes: 4},
			wantError: "expanded size exceeds the 4-byte limit",
		},
	}

	for _, format := range []string{"zip", "tar.gz"} {
		for _, tt := range tests {
			t.Run(format+"/"+tt.name, func(t *testing.T) {
				archivePath := writeLimitTestArchive(t, format, tt.entries)
				targetDir := t.TempDir()
				err := extractLimitTestArchive(format, archivePath, targetDir, tt.limits)
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("extract archive error = %v, want %q", err, tt.wantError)
				}
				if format == "zip" {
					extracted, readErr := os.ReadDir(targetDir)
					if readErr != nil {
						t.Fatalf("read zip extraction directory: %v", readErr)
					}
					if len(extracted) != 0 {
						t.Fatalf("zip preflight wrote %d entries before rejecting archive", len(extracted))
					}
				}
			})
		}
	}
}

func TestWriteArchiveFileRemovesPartialFileAtLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugin")
	written, err := writeArchiveFile(path, strings.NewReader("abcde"), 0o755, "plugin", 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds the 4-byte expanded size limit") {
		t.Fatalf("writeArchiveFile() error = %v", err)
	}
	if written != 4 {
		t.Fatalf("written = %d, want 4", written)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("partial archive entry remains at %q", path)
	}
}

type testArchiveEntry struct {
	name string
	body string
}

func writeLimitTestArchive(t *testing.T, format string, entries []testArchiveEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plugin."+format)
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}

	switch format {
	case "zip":
		writer := zip.NewWriter(file)
		for _, entry := range entries {
			part, createErr := writer.Create(entry.name)
			if createErr != nil {
				t.Fatalf("create zip entry %q: %v", entry.name, createErr)
			}
			if _, writeErr := io.WriteString(part, entry.body); writeErr != nil {
				t.Fatalf("write zip entry %q: %v", entry.name, writeErr)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close zip writer: %v", err)
		}
	case "tar.gz":
		gzipWriter := gzip.NewWriter(file)
		writer := tar.NewWriter(gzipWriter)
		for _, entry := range entries {
			header := &tar.Header{
				Name: entry.name,
				Mode: 0o755,
				Size: int64(len(entry.body)),
			}
			if err := writer.WriteHeader(header); err != nil {
				t.Fatalf("create tar entry %q: %v", entry.name, err)
			}
			if _, err := io.WriteString(writer, entry.body); err != nil {
				t.Fatalf("write tar entry %q: %v", entry.name, err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close tar writer: %v", err)
		}
		if err := gzipWriter.Close(); err != nil {
			t.Fatalf("close gzip writer: %v", err)
		}
	default:
		t.Fatalf("unsupported test archive format %q", format)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return path
}

func extractLimitTestArchive(format, archivePath, targetDir string, limits archiveLimits) error {
	switch format {
	case "zip":
		return extractZipArchive(archivePath, targetDir, limits)
	case "tar.gz":
		return extractTarGzArchive(archivePath, targetDir, limits)
	default:
		return fmt.Errorf("unsupported test archive format %q", format)
	}
}
