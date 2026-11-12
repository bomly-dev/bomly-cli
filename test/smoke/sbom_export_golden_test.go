//go:build smoke

package smoke

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// The exported SBOM is the artifact most consumers actually read, and it had
// no golden: TestScanSBOMExportOrigin asserts the origin fields it was written
// for, and nothing pinned the document's shape. ADR-0041 changed exactly that
// shape -- which components appear at all, since the project's own modules are
// no longer packages, plus the primary component, digests, and licenses -- so
// a regression there would have reached a user before it reached a test.
//
// Every format is exported from one scan so they cannot drift apart: they
// describe the same graph, and a component present in one and missing from the
// other is a defect neither format's own assertions would catch. SPDX 3.0 is
// converted from the same projection SPDX 2.3 writes, so its golden pins what
// that conversion keeps.
func TestScanSBOMExportGolden(t *testing.T) {
	t.Parallel()
	requireTool(t, "npm")

	outputDir := t.TempDir()
	spdxPath := filepath.Join(outputDir, "out.spdx.json")
	cdxPath := filepath.Join(outputDir, "out.cdx.json")
	spdx3Path := filepath.Join(outputDir, "out.spdx3.json")

	_, stderr, code := runBomly(t,
		// Pinned to the tag, like the sibling workspace case. On "main" this
		// golden tracks whatever the fixture repository last committed, so
		// smoke CI fails for a change to that repository rather than to
		// Bomly -- and the ref itself reaches the document, as the project
		// root's generic package URL.
		"scan", "--url", "https://github.com/bomly-dev/example-javascript-npm-workspaces", "--ref", "v1.0.0",
		"--detectors", "npm", "--format", "json",
		"-o", "spdx="+spdxPath, "-o", "cyclonedx="+cdxPath, "-o", "spdx3="+spdx3Path,
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
		{golden: "sbom-export-spdx3", path: spdx3Path},
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

	// SPDX 3: the creation info is a node of the @graph.
	graph, _ := doc["@graph"].([]any)
	for _, node := range graph {
		if object, ok := node.(map[string]any); ok && object["type"] == "CreationInfo" {
			if _, has := object["created"]; has {
				object["created"] = "<timestamp>"
			}
		}
	}

	normalizeSyntheticIDs(doc)
	normalizeSBOMStrings(doc)
	normalizeToolVersions(doc)

	// SPDX 3 orders its graph and element lists by identifier, and the tool
	// version is part of some identifiers; re-sorting after it is masked
	// keeps a release bump from reordering the golden.
	if graph != nil {
		sortSPDX3Graph(graph)
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("normalizeSBOMDocument: marshal: %v", err)
	}
	return append(out, '\n')
}

// sortSPDX3Graph orders an SPDX 3 @graph by element identifier and each
// collection's element list lexically, as the encoder does.
func sortSPDX3Graph(graph []any) {
	key := func(node any) string {
		object, _ := node.(map[string]any)
		for _, field := range []string{"spdxId", "@id"} {
			if id, ok := object[field].(string); ok {
				return id
			}
		}
		return ""
	}
	for _, node := range graph {
		if object, ok := node.(map[string]any); ok {
			if elements, ok := object["element"].([]any); ok {
				sort.SliceStable(elements, func(i, j int) bool {
					return fmt.Sprint(elements[i]) < fmt.Sprint(elements[j])
				})
			}
		}
	}
	sort.SliceStable(graph, func(i, j int) bool { return key(graph[i]) < key(graph[j]) })
}

// normalizeToolVersions blanks the version of the bomly-cli tool component.
//
// SPDX writes the tool as one string ("bomly-cli-0.24.2"), which the string
// normalizer above catches. CycloneDX writes name and version as separate
// fields, so the version survived it and the golden carried a literal release
// number -- which would fail this test on the next version bump, for exactly
// the volatile value the comment says is ignored.
func normalizeToolVersions(node any) {
	switch v := node.(type) {
	case map[string]any:
		if name, ok := v["name"].(string); ok && name == "bomly-cli" {
			if _, has := v["version"]; has {
				v["version"] = "<version>"
			}
		}
		for _, val := range v {
			normalizeToolVersions(val)
		}
	case []any:
		for _, child := range v {
			normalizeToolVersions(child)
		}
	}
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
