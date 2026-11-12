package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
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

// The SPDX 3 validator is taken out of its release archive by name alone and
// written to a fixed path: a nested directory is fine, while a link, a second
// copy, or a missing executable is refused.
func TestExtractSBOMToolsTakesOnlyTheExecutable(t *testing.T) {
	for name, testCase := range map[string]struct {
		entries []tarEntry
		want    string
		fails   string
	}{
		"nested executable": {
			entries: []tarEntry{{name: "sbom-tools-linux/README.md", body: "docs"}, {name: "sbom-tools-linux/sbom-tools", body: "binary"}},
			want:    "binary",
		},
		"root executable": {
			entries: []tarEntry{{name: "sbom-tools", body: "binary"}},
			want:    "binary",
		},
		"link named like the executable": {
			entries: []tarEntry{{name: "sbom-tools", link: "/bin/sh"}},
			fails:   "does not contain",
		},
		"two executables": {
			entries: []tarEntry{{name: "a/sbom-tools", body: "one"}, {name: "b/sbom-tools", body: "two"}},
			fails:   "more than one",
		},
		"no executable": {
			entries: []tarEntry{{name: "../../sbom-tools-evil", body: "x"}},
			fails:   "does not contain",
		},
	} {
		t.Run(name, func(t *testing.T) {
			archive := writeTestTarGz(t, testCase.entries)
			destination := t.TempDir()
			path, err := extractSBOMTools(archive, destination)
			if testCase.fails != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.fails) {
					t.Fatalf("err = %v, want it to mention %q", err, testCase.fails)
				}
				return
			}
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			if path != filepath.Join(destination, sbomToolsBinary) {
				t.Fatalf("path = %q, want the fixed destination", path)
			}
			body, err := os.ReadFile(path)
			if err != nil || string(body) != testCase.want {
				t.Fatalf("extracted %q (%v), want %q", body, err, testCase.want)
			}
		})
	}
}

type tarEntry struct {
	name string
	body string
	link string
}

func writeTestTarGz(t *testing.T, entries []tarEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "archive.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: 0o755, Typeflag: tar.TypeReg, Size: int64(len(entry.body))}
		if entry.link != "" {
			header = &tar.Header{Name: entry.name, Typeflag: tar.TypeSymlink, Linkname: entry.link}
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if entry.link == "" {
			if _, err := archive.Write([]byte(entry.body)); err != nil {
				t.Fatalf("write entry: %v", err)
			}
		}
	}
	for _, closer := range []interface{ Close() error }{archive, compressed, file} {
		if err := closer.Close(); err != nil {
			t.Fatalf("close archive: %v", err)
		}
	}
	return path
}

func TestCLIFormatForEachGeneratedDocument(t *testing.T) {
	for name, want := range map[string]string{
		"spdx-2.3-json":             "spdx",
		"spdx-2.3-json-merged":      "spdx",
		"spdx-3.0-json":             "spdx3",
		"spdx-3.0-json-merged":      "spdx3",
		"cyclonedx-1.7-json":        "cyclonedx",
		"cyclonedx-1.7-json-merged": "cyclonedx",
	} {
		if got := cliFormatFor(name); got != want {
			t.Errorf("cliFormatFor(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestEvaluateMergedLinks(t *testing.T) {
	wanted := map[string]struct{}{"https://a.example/ns": {}, "https://b.example/ns": {}}
	for name, testCase := range map[string]struct {
		format   mergedFormat
		document string
		passed   bool
		contains string
	}{
		"cyclonedx links both sources": {
			format:   mergedCycloneDX,
			document: `{"serialNumber":"urn:uuid:3f2b","externalReferences":[{"type":"bom","url":"https://a.example/ns"},{"type":"bom","url":"https://b.example/ns"},{"type":"website","url":"https://c.example"}]}`,
			passed:   true, contains: "links 2 source(s)",
		},
		"cyclonedx misses one source": {
			format:   mergedCycloneDX,
			document: `{"serialNumber":"urn:uuid:3f2b","externalReferences":[{"type":"bom","url":"https://a.example/ns"}]}`,
			contains: "does not link its sources: https://b.example/ns",
		},
		"cyclonedx only non-bom references": {
			format:   mergedCycloneDX,
			document: `{"serialNumber":"urn:uuid:3f2b","externalReferences":[{"type":"website","url":"https://a.example/ns"}]}`,
			contains: "does not link its sources",
		},
		"cyclonedx adopted a source's identity": {
			format:   mergedCycloneDX,
			document: `{"serialNumber":"https://a.example/ns","externalReferences":[{"type":"bom","url":"https://a.example/ns"},{"type":"bom","url":"https://b.example/ns"}]}`,
			contains: "adopted a source's identity",
		},
		// bomly-dev/bomly-cli#497: serialNumber is optional in CycloneDX, so
		// the official validator accepts its absence, and an empty identity is
		// never one of the sources'. The check has to ask for it explicitly.
		"cyclonedx has no serialNumber": {
			format:   mergedCycloneDX,
			document: `{"externalReferences":[{"type":"bom","url":"https://a.example/ns"},{"type":"bom","url":"https://b.example/ns"}]}`,
			contains: "has no serialNumber of its own",
		},
		"cyclonedx has a blank serialNumber": {
			format:   mergedCycloneDX,
			document: `{"serialNumber":"  ","externalReferences":[{"type":"bom","url":"https://a.example/ns"},{"type":"bom","url":"https://b.example/ns"}]}`,
			contains: "has no serialNumber of its own",
		},
		"spdx links both sources": {
			format:   mergedSPDX,
			document: `{"documentNamespace":"https://bomly.dev/spdx/3f2b","externalDocumentRefs":[{"externalDocumentId":"DocumentRef-a","spdxDocument":"https://a.example/ns","checksum":{"algorithm":"SHA1","checksumValue":"0"}},{"externalDocumentId":"DocumentRef-b","spdxDocument":"https://b.example/ns","checksum":{"algorithm":"SHA1","checksumValue":"0"}}]}`,
			passed:   true, contains: "links 2 source(s)",
		},
		"spdx misses one source": {
			format:   mergedSPDX,
			document: `{"documentNamespace":"https://bomly.dev/spdx/3f2b","externalDocumentRefs":[{"spdxDocument":"https://a.example/ns"}]}`,
			contains: "does not link its sources: https://b.example/ns",
		},
		"spdx adopted a source's identity": {
			format:   mergedSPDX,
			document: `{"documentNamespace":"https://b.example/ns","externalDocumentRefs":[{"spdxDocument":"https://a.example/ns"},{"spdxDocument":"https://b.example/ns"}]}`,
			contains: "adopted a source's identity: https://b.example/ns",
		},
		"spdx3 links both sources": {
			format:   mergedSPDX3,
			document: `{"@graph":[{"type":"software_Package","spdxId":"x"},{"type":"SpdxDocument","spdxId":"https://bomly.dev/spdx/3f2b#","import":[{"type":"ExternalMap","externalSpdxId":"DocumentRef-a","locationHint":"https://a.example/ns"},{"type":"ExternalMap","externalSpdxId":"DocumentRef-b","locationHint":"https://b.example/ns"}]}]}`,
			passed:   true, contains: "links 2 source(s)",
		},
		"spdx3 misses one source": {
			format:   mergedSPDX3,
			document: `{"@graph":[{"type":"SpdxDocument","spdxId":"https://bomly.dev/spdx/3f2b#","import":[{"locationHint":"https://a.example/ns"}]}]}`,
			contains: "does not link its sources: https://b.example/ns",
		},
		"spdx3 adopted a source's identity": {
			format:   mergedSPDX3,
			document: `{"@graph":[{"type":"SpdxDocument","spdxId":"https://b.example/ns#","import":[{"locationHint":"https://a.example/ns"},{"locationHint":"https://b.example/ns"}]}]}`,
			contains: "adopted a source's identity: https://b.example/ns",
		},
		"spdx3 has no SpdxDocument": {
			format:   mergedSPDX3,
			document: `{"@graph":[{"type":"software_Package","spdxId":"x"}]}`,
			contains: "has no SpdxDocument spdxId of its own",
		},
		"spdx has no documentNamespace": {
			format:   mergedSPDX,
			document: `{"externalDocumentRefs":[{"spdxDocument":"https://a.example/ns"},{"spdxDocument":"https://b.example/ns"}]}`,
			contains: "has no documentNamespace of its own",
		},
	} {
		t.Run(name, func(t *testing.T) {
			verdict, err := evaluateMergedLinks(testCase.format, []byte(testCase.document), wanted)
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
	for _, format := range []mergedFormat{mergedCycloneDX, mergedSPDX, mergedSPDX3} {
		if _, err := evaluateMergedLinks(format, []byte("{"), wanted); err == nil {
			t.Fatalf("%s: expected malformed JSON to be reported", format)
		}
	}
	if _, err := evaluateMergedLinks(mergedSPDX3, []byte(`{"@graph":[{"type":"SpdxDocument","spdxId":"a"},{"type":"SpdxDocument","spdxId":"b"}]}`), wanted); err == nil {
		t.Fatal("expected a document with two SpdxDocument elements to be reported")
	}
	if _, err := evaluateMergedLinks("tab-separated", []byte("{}"), wanted); err == nil {
		t.Fatal("expected an unknown format to be reported")
	}
	if _, err := spdxNamespace([]byte(`{"spdxVersion":"SPDX-2.3"}`)); err == nil {
		t.Fatal("expected a document without documentNamespace to be reported")
	}
	if _, err := spdxNamespace([]byte(`{"documentNamespace":" "}`)); err == nil {
		t.Fatal("expected a document with a blank documentNamespace to be reported")
	}
}

// TestMergedDocumentIdentityIsCheckedBeforeLinks pins the order of the merge
// rule: a document with no identity of its own is reported for that, not for
// whichever link it also happens to miss, so the detail names the actual gap.
func TestMergedDocumentIdentityIsCheckedBeforeLinks(t *testing.T) {
	wanted := map[string]struct{}{"https://a.example/ns": {}}
	verdict, err := evaluateMergedLinks(mergedCycloneDX, []byte(`{"externalReferences":[]}`), wanted)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if verdict.passed || !strings.Contains(verdict.detail, "has no serialNumber of its own") {
		t.Fatalf("verdict = %+v, want the missing identity reported first", verdict)
	}
}

// FuzzEvaluateMergedLinks pins that the link check never panics and answers
// the same way twice for any document handed to it.
func FuzzEvaluateMergedLinks(f *testing.F) {
	f.Add([]byte(`{"serialNumber":"urn:uuid:1","externalReferences":[{"type":"bom","url":"https://a.example/ns"}]}`))
	f.Add([]byte(`{"externalReferences":[{"type":"bom"}]}`))
	f.Add([]byte(`{"externalReferences":[{"type":"bom","url":"https://a.example/ns"}]}`))
	f.Add([]byte(`{"serialNumber":"","externalReferences":[{"type":"bom","url":"https://a.example/ns"}]}`))
	f.Add([]byte(`{"serialNumber":"https://a.example/ns"}`))
	f.Add([]byte(`{"documentNamespace":"https://bomly.dev/spdx/1","externalDocumentRefs":[{"spdxDocument":"https://a.example/ns"}]}`))
	f.Add([]byte(`{"externalDocumentRefs":[{"spdxDocument":"https://a.example/ns"}]}`))
	f.Add([]byte(`{"documentNamespace":"https://a.example/ns"}`))
	f.Add([]byte(`{"@graph":[{"type":"SpdxDocument","spdxId":"https://bomly.dev/spdx/1#","import":[{"locationHint":"https://a.example/ns"}]}]}`))
	f.Add([]byte(`{"@graph":[{"type":"SpdxDocument","spdxId":"https://a.example/ns#"}]}`))
	f.Add([]byte(`{"@graph":[{"type":"SpdxDocument"},{"type":"SpdxDocument"}]}`))
	f.Add([]byte(`{"@graph":{}}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testkit.MaxFuzzInputSize {
			t.Skip("input exceeds the shared fuzz bound")
		}
		wanted := map[string]struct{}{"https://a.example/ns": {}}
		for _, format := range []mergedFormat{mergedCycloneDX, mergedSPDX, mergedSPDX3} {
			first, firstErr := evaluateMergedLinks(format, data, wanted)
			second, secondErr := evaluateMergedLinks(format, data, wanted)
			if (firstErr == nil) != (secondErr == nil) || first != second {
				t.Fatalf("%s non-deterministic: %+v/%v then %+v/%v", format, first, firstErr, second, secondErr)
			}
			if firstErr == nil && first.passed && strings.TrimSpace(first.detail) == "" {
				t.Fatalf("%s passed without a detail", format)
			}
		}
		_, nsErr := spdxNamespace(data)
		_, nsErr2 := spdxNamespace(data)
		if (nsErr == nil) != (nsErr2 == nil) {
			t.Fatal("spdxNamespace is non-deterministic")
		}
	})
}
