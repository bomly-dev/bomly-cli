package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/testkit"
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

func TestEvaluateMergedLinks(t *testing.T) {
	wanted := map[string]struct{}{"https://a.example/ns": {}, "https://b.example/ns": {}}
	for name, testCase := range map[string]struct {
		document string
		passed   bool
		contains string
	}{
		"links both sources": {
			document: `{"serialNumber":"urn:uuid:3f2b","externalReferences":[{"type":"bom","url":"https://a.example/ns"},{"type":"bom","url":"https://b.example/ns"},{"type":"website","url":"https://c.example"}]}`,
			passed:   true, contains: "links 2 source(s)",
		},
		"misses one source": {
			document: `{"serialNumber":"urn:uuid:3f2b","externalReferences":[{"type":"bom","url":"https://a.example/ns"}]}`,
			contains: "does not link its sources: https://b.example/ns",
		},
		"only non-bom references": {
			document: `{"serialNumber":"urn:uuid:3f2b","externalReferences":[{"type":"website","url":"https://a.example/ns"}]}`,
			contains: "does not link its sources",
		},
		"adopted a source's identity": {
			document: `{"serialNumber":"https://a.example/ns","externalReferences":[{"type":"bom","url":"https://a.example/ns"},{"type":"bom","url":"https://b.example/ns"}]}`,
			contains: "adopted a source's identity",
		},
	} {
		t.Run(name, func(t *testing.T) {
			verdict, err := evaluateMergedLinks([]byte(testCase.document), wanted)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if verdict.passed != testCase.passed {
				t.Fatalf("passed = %v, want %v (%s)", verdict.passed, testCase.passed, verdict.detail)
			}
			if !strings.Contains(verdict.detail, testCase.contains) {
				t.Fatalf("detail = %q, want it to mention %q", verdict.detail, testCase.contains)
			}
		})
	}
	if _, err := evaluateMergedLinks([]byte("{"), wanted); err == nil {
		t.Fatal("expected malformed JSON to be reported")
	}
	if _, err := spdxNamespace([]byte(`{"spdxVersion":"SPDX-2.3"}`)); err == nil {
		t.Fatal("expected a document without documentNamespace to be reported")
	}
}

// FuzzEvaluateMergedLinks pins that the link check never panics and answers
// the same way twice for any document handed to it.
func FuzzEvaluateMergedLinks(f *testing.F) {
	f.Add([]byte(`{"serialNumber":"urn:uuid:1","externalReferences":[{"type":"bom","url":"https://a.example/ns"}]}`))
	f.Add([]byte(`{"externalReferences":[{"type":"bom"}]}`))
	f.Add([]byte(`{"serialNumber":"https://a.example/ns"}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testkit.MaxFuzzInputSize {
			t.Skip("input exceeds the shared fuzz bound")
		}
		wanted := map[string]struct{}{"https://a.example/ns": {}}
		first, firstErr := evaluateMergedLinks(data, wanted)
		second, secondErr := evaluateMergedLinks(data, wanted)
		if (firstErr == nil) != (secondErr == nil) || first != second {
			t.Fatalf("non-deterministic: %+v/%v then %+v/%v", first, firstErr, second, secondErr)
		}
		_, nsErr := spdxNamespace(data)
		_, nsErr2 := spdxNamespace(data)
		if (nsErr == nil) != (nsErr2 == nil) {
			t.Fatal("spdxNamespace is non-deterministic")
		}
	})
}
