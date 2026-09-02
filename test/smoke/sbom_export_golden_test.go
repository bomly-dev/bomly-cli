//go:build smoke

package smoke

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The exported SBOM is the artifact most consumers actually read, and it had
// no golden: TestScanSBOMExportOrigin asserts the origin fields it was written
// for, and nothing pinned the document's shape. ADR-0041 changed exactly that
// shape -- which components appear at all, since the project's own modules are
// no longer packages, plus the primary component, digests, and licenses -- so
// a regression there would have reached a user before it reached a test.
//
// Both formats are exported from one scan so they cannot drift apart: they
// describe the same graph, and a component present in one and missing from the
// other is a defect neither format's own assertions would catch.
func TestScanSBOMExportGolden(t *testing.T) {
	t.Parallel()
	requireTool(t, "npm")

	outputDir := t.TempDir()
	spdxPath := filepath.Join(outputDir, "out.spdx.json")
	cdxPath := filepath.Join(outputDir, "out.cdx.json")

	_, stderr, code := runBomly(t,
		"scan", "--url", "https://github.com/bomly-dev/example-javascript-npm-workspaces", "--ref", "main",
		"--detectors", "npm", "--format", "json",
		"-o", "spdx="+spdxPath, "-o", "cyclonedx="+cdxPath,
	)
	if code != 0 {
		t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
	}

	for _, export := range []struct {
		golden string
		path   string
	}{
		{golden: "sbom-export-spdx", path: spdxPath},
		{golden: "sbom-export-cyclonedx", path: cdxPath},
	} {
		raw, err := os.ReadFile(export.path)
		if err != nil {
			t.Fatalf("read %s: %v", export.golden, err)
		}
		assertGoldenDocument(t, export.golden, normalizeSBOMDocument(t, raw))
	}
}

// reSPDXNamespace matches the document namespace SPDX requires to be unique
// per document, and reUUID the CycloneDX serial number. Both are minted fresh
// on every export by design, so both are placeholders in a golden.
var (
	reSPDXNamespace = regexp.MustCompile(`https://bomly\.dev/spdx/[0-9a-fA-F-]+`)
	reUUID          = regexp.MustCompile(`urn:uuid:[0-9a-fA-F-]+`)
	reToolVersion   = regexp.MustCompile(`(bomly-cli)-\d+\.\d+\.\d+`)
)

// normalizeSBOMDocument replaces the fields an SBOM is required to make unique
// or timestamped, then re-encodes so the golden is stable and readable.
//
// The tool version is normalized too: it tracks the release, so leaving it in
// would make every golden fail on the next version bump for a reason that has
// nothing to do with what the document says about the project.
func normalizeSBOMDocument(t *testing.T, raw []byte) []byte {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("normalizeSBOMDocument: unmarshal: %v\nraw:\n%s", err, string(raw))
	}

	// SPDX: creationInfo.created, and the document namespace.
	if info, ok := doc["creationInfo"].(map[string]any); ok {
		if _, has := info["created"]; has {
			info["created"] = "<timestamp>"
		}
	}
	// CycloneDX: metadata.timestamp.
	if metadata, ok := doc["metadata"].(map[string]any); ok {
		if _, has := metadata["timestamp"]; has {
			metadata["timestamp"] = "<timestamp>"
		}
	}

	normalizeSyntheticIDs(doc)
	normalizeSBOMStrings(doc)

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("normalizeSBOMDocument: marshal: %v", err)
	}
	return append(out, '\n')
}

// normalizeSBOMStrings rewrites the per-document unique values wherever they
// appear -- they are referenced from more than one field, so replacing them
// only at the top level would leave a copy behind.
func normalizeSBOMStrings(node any) {
	replace := func(s string) string {
		s = reSPDXNamespace.ReplaceAllString(s, "https://bomly.dev/spdx/<uuid>")
		s = reUUID.ReplaceAllString(s, "urn:uuid:<uuid>")
		return reToolVersion.ReplaceAllString(s, "${1}-<version>")
	}
	switch v := node.(type) {
	case map[string]any:
		for k, val := range v {
			if s, ok := val.(string); ok {
				v[k] = replace(s)
				continue
			}
			normalizeSBOMStrings(val)
		}
	case []any:
		for idx, child := range v {
			if s, ok := child.(string); ok {
				v[idx] = replace(s)
				continue
			}
			normalizeSBOMStrings(child)
		}
	}
}
