package assurance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func baseFor(id string, stage Stage, level Level) CheckResult {
	return CheckResult{SchemaVersion: CheckSchema, ID: id, Stage: stage, Level: level}
}

func TestConvertBenchmarkRun(t *testing.T) {
	manifest := map[string]any{
		"schema_version": BenchmarkRunSchema,
		"case":           map[string]any{"name": "canonical-sbom-scan", "samples_per_mode": 5},
		"summaries": []map[string]any{
			{"mode": "cold", "samples": 5, "median_ms": 412.4, "mean_ms": 430.0,
				"confidence_interval_95_ms": []float64{400, 460}, "peak_memory_bytes": 91234304},
			{"mode": "warm", "samples": 5, "median_ms": 288.1, "mean_ms": 291.0,
				"confidence_interval_95_ms": []float64{280, 300}, "peak_memory_bytes": 80234304},
		},
		"gates": map[string]any{"passed": true},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	result, err := ConvertBenchmarkRun(data, baseFor("perf-samples", StagePostRelease, LevelAdvisory))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("converted result invalid: %v", err)
	}
	if result.Status != StatusPass {
		t.Fatalf("status = %s, want pass", result.Status)
	}
	if result.Metrics["cold_median_ms"] != 412.4 || result.Metrics["warm_median_ms"] != 288.1 {
		t.Fatalf("metrics = %v", result.Metrics)
	}
	if result.Metrics["peak_memory_bytes"] != 91234304 {
		t.Fatalf("peak memory = %v", result.Metrics["peak_memory_bytes"])
	}
	if len(result.Details) != 2 {
		t.Fatalf("details = %+v", result.Details)
	}
}

func TestConvertBenchmarkRunFailedGate(t *testing.T) {
	data := []byte(`{"schema_version":"bomly.benchmark-run/v1","case":{"name":"c","samples_per_mode":5},
	"summaries":[],"gates":{"passed":false,"failure_reason":"normalized output changed between samples"}}`)
	result, err := ConvertBenchmarkRun(data, baseFor("perf-samples", StagePostRelease, LevelAdvisory))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if result.Status != StatusFail {
		t.Fatalf("status = %s, want fail", result.Status)
	}
	if !strings.Contains(result.Summary, "normalized output changed") {
		t.Fatalf("summary = %q", result.Summary)
	}
}

func TestConvertSBOMAssurance(t *testing.T) {
	data := []byte(`{"schema_version":"bomly.sbom-assurance-run/v1",
	"validators":[{"name":"spdx-tools-java","version":"2.0.7","sha256":"2dc63c3399c5178058b1be8a3de6f13b9f24981cd86c4292ef98f4a7e90de36d"},
	              {"name":"cyclonedx-cli","version":"0.32.0","sha256":"454879e6a4a405c8a13bff49b8982adcb0596f3019b26b0811c66e4d7f0783e1"}],
	"artifacts":[{"format":"spdx-2.3-json","path":"a.json","sha256":"aa","bytes":120},
	             {"format":"cyclonedx-1.7-json","path":"b.json","sha256":"bb","bytes":140}],
	"commands":[{"executable":"/usr/bin/java","args":["-jar","tools.jar","Verify"],"exit_code":0,"duration_ms":900}]}`)
	result, err := ConvertSBOMAssurance(data, baseFor("sbom-interoperability", StagePostRelease, LevelGate))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("converted result invalid: %v", err)
	}
	if result.Status != StatusPass {
		t.Fatalf("status = %s, want pass", result.Status)
	}
	if len(result.Artifacts) != 2 {
		t.Fatalf("artifacts = %+v", result.Artifacts)
	}
	if !strings.Contains(result.Summary, "spdx-tools-java 2.0.7") {
		t.Fatalf("summary = %q", result.Summary)
	}
}

func TestConvertSBOMAssuranceRecordsFailure(t *testing.T) {
	data := []byte(`{"schema_version":"bomly.sbom-assurance-run/v1","validators":[],"artifacts":[],
	"commands":[{"executable":"cyclonedx-cli","args":["validate"],"exit_code":1,"duration_ms":10}],
	"failure":"validator cyclonedx-cli failed with exit 1"}`)
	result, err := ConvertSBOMAssurance(data, baseFor("sbom-interoperability", StagePostRelease, LevelGate))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if result.Status != StatusFail || !strings.Contains(result.Summary, "validator cyclonedx-cli failed") {
		t.Fatalf("result = %+v", result)
	}
}

func TestConvertRejectsWrongSchema(t *testing.T) {
	if _, err := ConvertBenchmarkRun([]byte(`{"schema_version":"other/v1"}`), CheckResult{}); err == nil {
		t.Fatal("expected the wrong schema to be rejected")
	}
	if _, err := ConvertSBOMAssurance([]byte(`{"schema_version":"other/v1"}`), CheckResult{}); err == nil {
		t.Fatal("expected the wrong schema to be rejected")
	}
}

func TestExpectedAssetsCoverEveryPlatform(t *testing.T) {
	assets := ExpectedAssets("0.23.0")
	if len(assets) != 23 {
		t.Fatalf("expected 23 release assets, got %d: %v", len(assets), assets)
	}
	for _, required := range []string{
		"SHA256SUMS", "SHA256SUMS.sigstore.json", "multiple.intoto.jsonl",
		"bomly_0.23.0_linux_amd64.tar.gz", "bomly-lite_0.23.0_windows_arm64.zip",
		"bomly_0.23.0_linux_arm64.pkg.tar.zst",
	} {
		if !contains(assets, required) {
			t.Fatalf("expected asset list to contain %s", required)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestParseSHA256SUMS(t *testing.T) {
	entries, err := ParseSHA256SUMS([]byte(
		"aa2c19f8a17ad4c65c6b6a41c9de9b8bbd9d3d3b1f1d6b0b5b0a67f6d4f1a2b3  bomly_1.0.0_linux_amd64.tar.gz\n" +
			"bb2c19f8a17ad4c65c6b6a41c9de9b8bbd9d3d3b1f1d6b0b5b0a67f6d4f1a2b3 *bomly_1.0.0_windows_amd64.zip\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %v", entries)
	}
	for _, broken := range []string{
		"not-a-hash  file.tar.gz\n",
		"aa2c19f8a17ad4c65c6b6a41c9de9b8bbd9d3d3b1f1d6b0b5b0a67f6d4f1a2b3  ../escape.tar.gz\n",
		"onlyonefield\n",
		"",
	} {
		if _, err := ParseSHA256SUMS([]byte(broken)); err == nil {
			t.Fatalf("expected %q to be rejected", broken)
		}
	}
}

func TestVerifyChecksumsDetectsProblems(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("binary\n")
	if err := os.WriteFile(filepath.Join(dir, "bomly_1.0.0_linux_amd64.tar.gz"), payload, 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stray.txt"), payload, 0o644); err != nil {
		t.Fatalf("write stray: %v", err)
	}
	entries := ChecksumEntries{
		"bomly_1.0.0_linux_amd64.tar.gz":  "1111111111111111111111111111111111111111111111111111111111111111",
		"bomly_1.0.0_darwin_arm64.tar.gz": "2222222222222222222222222222222222222222222222222222222222222222",
	}
	outcome, err := VerifyChecksums(dir, entries)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(outcome.Mismatched) != 1 || len(outcome.Unlisted) != 1 || len(outcome.NotDownloaded) != 1 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestArchiveNameUsesZipOnWindows(t *testing.T) {
	if got := ArchiveName("bomly", "1.2.3", "windows", "arm64"); got != "bomly_1.2.3_windows_arm64.zip" {
		t.Fatalf("archive name = %s", got)
	}
	if got := ArchiveName("bomly-lite", "1.2.3", runtime.GOOS, "amd64"); !strings.Contains(got, "1.2.3") {
		t.Fatalf("archive name = %s", got)
	}
}
