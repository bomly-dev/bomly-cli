package qa_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/test/qa"
)

func TestBuildQASummaryDerivesRelationshipAndScopeCounts(t *testing.T) {
	dir := t.TempDir()
	bomlyPath := filepath.Join(dir, "bomly.sbom.json")
	githubPath := filepath.Join(dir, "github.sbom.json")
	diffPath := filepath.Join(dir, "diff.json")

	writeFile(t, bomlyPath, `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "bomly",
  "documentNamespace": "https://example.com/bomly",
  "creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: bomly"]},
  "packages": [
    {"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "comment": "bomly:scope=runtime", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/app@1.0.0"}]},
    {"SPDXID": "SPDXRef-left", "name": "left-pad", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "comment": "bomly:scope=development", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.0.0"}]},
    {"SPDXID": "SPDXRef-extra", "name": "extra", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/extra@1.0.0"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-app", "relationshipType": "DESCRIBES"},
    {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-left", "relationshipType": "DEPENDS_ON"},
    {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-extra", "relationshipType": "DEPENDS_ON"}
  ]
}`)
	writeFile(t, githubPath, `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "github",
  "documentNamespace": "https://example.com/github",
  "creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: github"]},
  "packages": [
    {"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/app@1.0.0"}]},
    {"SPDXID": "SPDXRef-left", "name": "left-pad", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.0.0"}]},
    {"SPDXID": "SPDXRef-github-only", "name": "github-only", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/github-only@1.0.0"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-app", "relationshipType": "DESCRIBES"},
    {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-left", "relationshipType": "DEPENDS_ON"},
    {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-github-only", "relationshipType": "DEPENDS_ON"}
  ]
}`)
	writeFile(t, diffPath, `{"summary":{"added_package_count":1,"changed_package_count":2,"removed_package_count":3}}`)

	summary, err := qa.BuildQASourceSummary("scan-npm", "github", bomlyPath, githubPath, diffPath, qa.SourceArtifacts{SBOM: "github.sbom.json", Diff: "github.diff.json", Summary: "github.qa-summary.json"})
	if err != nil {
		t.Fatalf("BuildQASourceSummary() error = %v", err)
	}
	if summary.Source != "github" {
		t.Fatalf("Source = %q, want github", summary.Source)
	}
	if summary.PackageDiff.AddedPackageCount != 1 || summary.PackageDiff.ChangedPackageCount != 2 || summary.PackageDiff.RemovedPackageCount != 3 {
		t.Fatalf("unexpected package summary: %#v", summary.PackageDiff)
	}
	if summary.Relationships.MatchedCount != 1 || summary.Relationships.BomlyOnlyCount != 1 || summary.Relationships.SourceOnlyCount != 1 {
		t.Fatalf("unexpected relationship summary: %#v", summary.Relationships)
	}
	if summary.BomlyScope.KnownScopeCount != 2 || summary.BomlyScope.UnknownScopeCount != 1 || summary.BomlyScope.Scopes["runtime"] != 1 {
		t.Fatalf("unexpected bomly scope summary: %#v", summary.BomlyScope)
	}
	if summary.SourceScope.KnownScopeCount != 0 || summary.SourceScope.UnknownScopeCount != 3 {
		t.Fatalf("unexpected source scope summary: %#v", summary.SourceScope)
	}
}

func TestBuildQASourceSummaryExtractsUsedDetectors(t *testing.T) {
	dir := t.TempDir()
	bomlyPath := filepath.Join(dir, "bomly.sbom.json")
	sourcePath := filepath.Join(dir, "source.sbom.json")
	diffPath := filepath.Join(dir, "diff.json")
	writeFile(t, bomlyPath, `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "bomly",
  "documentNamespace": "https://example.com/bomly",
  "creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: bomly-cli", "Tool: bomly-detector:npm-detector"]},
  "packages": []
}`)
	writeFile(t, sourcePath, `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "source",
  "documentNamespace": "https://example.com/source",
  "creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: source"]},
  "packages": []
}`)
	writeFile(t, diffPath, `{"summary":{}}`)

	summary, err := qa.BuildQASourceSummary("scan-npm", "syft", bomlyPath, sourcePath, diffPath, qa.SourceArtifacts{})
	if err != nil {
		t.Fatalf("BuildQASourceSummary() error = %v", err)
	}
	if len(summary.Detectors) != 1 || summary.Detectors[0] != "npm-detector" {
		t.Fatalf("Detectors = %#v, want npm-detector", summary.Detectors)
	}
}

func TestBuildQASummaryAggregatesSourceStatuses(t *testing.T) {
	summary := qa.BuildQASummary("scan-npm", []qa.QASourceSummary{
		{Case: "scan-npm", Source: "github", Status: "completed"},
		{Case: "scan-npm", Source: "syft", Status: "skipped", Reason: "missing required tool: syft"},
	}, []string{"npm-detector"})
	if summary.Status != "completed" {
		t.Fatalf("Status = %q, want completed", summary.Status)
	}
	if len(summary.Sources) != 2 {
		t.Fatalf("expected 2 source summaries, got %#v", summary.Sources)
	}
	if len(summary.Detectors) != 1 || summary.Detectors[0] != "npm-detector" {
		t.Fatalf("Detectors = %#v", summary.Detectors)
	}

	summary = qa.BuildQASummary("scan-npm", []qa.QASourceSummary{
		{Case: "scan-npm", Source: "github", Status: "failed"},
	}, nil)
	if summary.Status != "failed" {
		t.Fatalf("Status = %q, want failed", summary.Status)
	}
}

func TestUnwrapGitHubSBOM(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "response.json")
	output := filepath.Join(dir, "github.sbom.json")
	writeFile(t, input, `{"sbom":{"spdxVersion":"SPDX-2.3","name":"repo"}}`)

	if err := qa.UnwrapGitHubSBOM(input, output); err != nil {
		t.Fatalf("UnwrapGitHubSBOM() error = %v", err)
	}
	var payload map[string]any
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if payload["spdxVersion"] != "SPDX-2.3" {
		t.Fatalf("unexpected output: %#v", payload)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
