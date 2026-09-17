// Command sbominterop generates canonical SBOMs and validates them with
// checksum-pinned upstream tools. It backs the SBOM interoperability check of
// Bomly's release assurance framework.
package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-sdk/system"
)

const (
	manifestSchema = "bomly.sbom-assurance-run/v1"

	spdxVersion  = "2.0.7"
	spdxURL      = "https://github.com/spdx/tools-java/releases/download/v2.0.7/tools-java-2.0.7.zip"
	spdxSHA256   = "2dc63c3399c5178058b1be8a3de6f13b9f24981cd86c4292ef98f4a7e90de36d"
	spdxJarName  = "tools-java-2.0.7-jar-with-dependencies.jar"
	maxSPDXJar   = 128 << 20
	cdxVersion   = "0.32.0"
	cdxURL       = "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.32.0/cyclonedx-linux-x64"
	cdxSHA256    = "454879e6a4a405c8a13bff49b8982adcb0596f3019b26b0811c66e4d7f0783e1"
	defaultInput = "test/smoke/testdata/sboms/go.spdx.json"
	// The merge case scans two source documents as one tree, so the export has
	// to reconcile two documents that each assert their own identity — the
	// case the single-fixture run never reaches.
	defaultMergeA = "test/smoke/testdata/sboms/go.spdx.json"
	defaultMergeB = "test/smoke/testdata/sboms/js.spdx.json"
	// maxDocumentBytes bounds the generated documents this tool reads back.
	maxDocumentBytes = 64 << 20
)

type runManifest struct {
	SchemaVersion string          `json:"schema_version"`
	StartedAt     string          `json:"started_at"`
	FinishedAt    string          `json:"finished_at"`
	Host          hostInfo        `json:"host"`
	Validators    []validatorInfo `json:"validators"`
	Artifacts     []artifactInfo  `json:"artifacts"`
	Commands      []commandResult `json:"commands"`
	// Checks are assertions about the generated documents that no external
	// validator makes, recorded alongside the validator runs.
	Checks  []checkInfo `json:"checks,omitempty"`
	Failure string      `json:"failure,omitempty"`
}

type checkInfo struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type hostInfo struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Go      string `json:"go_version"`
	Network bool   `json:"network_enabled"`
}

type validatorInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

type artifactInfo struct {
	Format string `json:"format"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type commandResult struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
	ExitCode   int      `json:"exit_code"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	DurationMS int64    `json:"duration_ms"`
}

func main() {
	var bomlyPath string
	var outputDir string
	var inputPath string
	flag.StringVar(&bomlyPath, "bomly", "./bin/bomly-lite", "path to the Bomly executable")
	flag.StringVar(&outputDir, "output", "sbom-assurance-artifacts", "artifact output directory")
	flag.StringVar(&inputPath, "input", defaultInput, "canonical input SBOM")
	var mergeA, mergeB string
	flag.StringVar(&mergeA, "merge-a", defaultMergeA, "first source document for the merged export")
	flag.StringVar(&mergeB, "merge-b", defaultMergeB, "second source document for the merged export")
	flag.Parse()

	if err := run(bomlyPath, outputDir, inputPath, mergeA, mergeB); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(bomlyPath, outputDir, inputPath, mergeA, mergeB string) error {
	started := time.Now().UTC()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("SBOM assurance requires linux/amd64, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	downloadDir := filepath.Join(outputDir, "validators")
	if err := os.MkdirAll(downloadDir, 0o755); err != nil {
		return fmt.Errorf("create validator directory: %w", err)
	}

	manifest := runManifest{
		SchemaVersion: manifestSchema,
		StartedAt:     started.Format(time.RFC3339Nano),
		Host: hostInfo{
			OS: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version(), Network: true,
		},
		Validators: []validatorInfo{
			{Name: "spdx-tools-java", Version: spdxVersion, URL: spdxURL, SHA256: spdxSHA256},
			{Name: "cyclonedx-cli", Version: cdxVersion, URL: cdxURL, SHA256: cdxSHA256},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	spdxArchive := filepath.Join(downloadDir, "tools-java-"+spdxVersion+".zip")
	if err := downloadVerified(ctx, spdxURL, spdxSHA256, spdxArchive); err != nil {
		return writeFailure(outputDir, &manifest, err)
	}
	spdxJar, err := extractSPDXJar(spdxArchive, downloadDir)
	if err != nil {
		return writeFailure(outputDir, &manifest, err)
	}
	cdxBinary := filepath.Join(downloadDir, "cyclonedx-cli")
	if err := downloadVerified(ctx, cdxURL, cdxSHA256, cdxBinary); err != nil {
		return writeFailure(outputDir, &manifest, err)
	}
	if err := os.Chmod(cdxBinary, 0o755); err != nil {
		return writeFailure(outputDir, &manifest, fmt.Errorf("mark CycloneDX validator executable: %w", err))
	}

	formats := []struct {
		name string
		path string
	}{
		{name: "spdx-2.3-json", path: filepath.Join(outputDir, "bomly.spdx.json")},
		{name: "cyclonedx-1.7-json", path: filepath.Join(outputDir, "bomly.cdx.json")},
	}
	for _, format := range formats {
		cliFormat := "spdx"
		if strings.HasPrefix(format.name, "cyclonedx") {
			cliFormat = "cyclonedx"
		}
		result, stdout := execute(ctx, bomlyPath, "scan", "--sbom", "--path", inputPath, "--detectors", "sbom", "--format", cliFormat)
		manifest.Commands = append(manifest.Commands, result)
		if result.ExitCode != 0 {
			return writeFailure(outputDir, &manifest, fmt.Errorf("generate %s: exit %d", format.name, result.ExitCode))
		}
		if err := os.WriteFile(format.path, stdout, 0o600); err != nil {
			return writeFailure(outputDir, &manifest, fmt.Errorf("write %s: %w", format.name, err))
		}
		artifact, err := describeArtifact(format.name, format.path)
		if err != nil {
			return writeFailure(outputDir, &manifest, err)
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}

	mergeTree := filepath.Join(outputDir, "merge-tree")
	if err := stageMergeTree(mergeTree, mergeA, mergeB); err != nil {
		return writeFailure(outputDir, &manifest, err)
	}
	merged := []struct {
		name string
		path string
	}{
		{name: "spdx-2.3-json-merged", path: filepath.Join(outputDir, "bomly-merged.spdx.json")},
		{name: "cyclonedx-1.7-json-merged", path: filepath.Join(outputDir, "bomly-merged.cdx.json")},
	}
	for _, format := range merged {
		cliFormat := "spdx"
		if strings.HasPrefix(format.name, "cyclonedx") {
			cliFormat = "cyclonedx"
		}
		result, stdout := execute(ctx, bomlyPath, "scan", "--path", mergeTree, "--recursive", "--detectors", "sbom", "--format", cliFormat)
		manifest.Commands = append(manifest.Commands, result)
		if result.ExitCode != 0 {
			return writeFailure(outputDir, &manifest, fmt.Errorf("generate %s: exit %d", format.name, result.ExitCode))
		}
		if err := os.WriteFile(format.path, stdout, 0o600); err != nil {
			return writeFailure(outputDir, &manifest, fmt.Errorf("write %s: %w", format.name, err))
		}
		artifact, err := describeArtifact(format.name, format.path)
		if err != nil {
			return writeFailure(outputDir, &manifest, err)
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}

	// A merged document states its own identity and names the documents it
	// was built from, rather than adopting one source's identity (ADR-0042).
	// Only a real two-source run can produce this, which is why it is asserted
	// here and not in a unit test.
	linkCheck, err := checkMergedDocumentLinks(merged[1].path, mergeA, mergeB)
	if err != nil {
		return writeFailure(outputDir, &manifest, err)
	}
	manifest.Checks = append(manifest.Checks, linkCheck)
	if !linkCheck.Passed {
		return writeFailure(outputDir, &manifest, errors.New(linkCheck.Detail))
	}

	commands := [][]string{
		{"java", "-jar", spdxJar, "Verify", formats[0].path},
		{cdxBinary, "validate", "--input-file", formats[1].path, "--input-format", "json", "--input-version", "v1_7", "--fail-on-errors"},
		{"java", "-jar", spdxJar, "Verify", merged[0].path},
		{cdxBinary, "validate", "--input-file", merged[1].path, "--input-format", "json", "--input-version", "v1_7", "--fail-on-errors"},
	}
	for _, command := range commands {
		result, _ := execute(ctx, command[0], command[1:]...)
		manifest.Commands = append(manifest.Commands, result)
		if result.ExitCode != 0 {
			return writeFailure(outputDir, &manifest, fmt.Errorf("validator %s failed with exit %d", filepath.Base(command[0]), result.ExitCode))
		}
	}

	manifest.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeManifest(outputDir, manifest)
}

func downloadVerified(ctx context.Context, url, wantSHA, destination string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create download request: %w", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %s", url, response.Status)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create download destination: %w", err)
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(file, hash), response.Body)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("download %s: %w", url, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close download %s: %w", url, closeErr)
	}
	gotSHA := hex.EncodeToString(hash.Sum(nil))
	if gotSHA != wantSHA {
		return fmt.Errorf("verify %s: SHA-256 %s, want %s", url, gotSHA, wantSHA)
	}
	return nil
}

func extractSPDXJar(archivePath, destination string) (string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("open SPDX validator archive: %w", err)
	}
	defer reader.Close()
	var source *zip.File
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() || entry.Name != spdxJarName {
			continue
		}
		if source != nil {
			return "", errors.New("SPDX validator archive contains duplicate executable jars")
		}
		source = entry
	}
	if source == nil {
		return "", fmt.Errorf("SPDX validator archive does not contain root entry %q", spdxJarName)
	}
	if source.UncompressedSize64 > maxSPDXJar {
		return "", fmt.Errorf("SPDX validator jar is %d bytes, limit %d", source.UncompressedSize64, maxSPDXJar)
	}
	input, err := source.Open()
	if err != nil {
		return "", fmt.Errorf("open SPDX validator jar: %w", err)
	}
	defer input.Close()
	jarPath := filepath.Join(destination, spdxJarName)
	output, err := os.OpenFile(jarPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create SPDX validator jar: %w", err)
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, maxSPDXJar+1))
	closeErr := output.Close()
	if copyErr != nil {
		return "", fmt.Errorf("extract SPDX validator jar: %w", copyErr)
	}
	if written > maxSPDXJar {
		return "", fmt.Errorf("SPDX validator jar exceeds %d-byte extraction limit", maxSPDXJar)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close SPDX validator jar: %w", closeErr)
	}
	return jarPath, nil
}

func execute(ctx context.Context, executable string, args ...string) (commandResult, []byte) {
	started := time.Now()
	command := exec.CommandContext(ctx, executable, args...)
	var stdout strings.Builder
	var stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	result := commandResult{
		Executable: executable,
		Args:       append([]string(nil), args...),
		ExitCode:   exitCode,
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		DurationMS: time.Since(started).Milliseconds(),
	}
	return result, []byte(stdout.String())
}

// stageMergeTree lays the two source documents out as sibling subprojects so
// one recursive scan has to reconcile them.
func stageMergeTree(tree, sourceA, sourceB string) error {
	for index, source := range []string{sourceA, sourceB} {
		directory := filepath.Join(tree, string(rune('a'+index)))
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return fmt.Errorf("create merge tree: %w", err)
		}
		data, err := system.ReadFileLimit(source, maxDocumentBytes)
		if err != nil {
			return fmt.Errorf("read merge source: %w", err)
		}
		if err := os.WriteFile(filepath.Join(directory, filepath.Base(source)), data, 0o600); err != nil {
			return fmt.Errorf("stage merge source: %w", err)
		}
	}
	return nil
}

// checkMergedDocumentLinks asserts the ADR-0042 merge rule on a generated
// CycloneDX document: every source's SPDX documentNamespace appears as a
// `bom` external reference, and the merged serial number is not one of them.
//
// The fields are read with plain JSON decoding on purpose. The SDK's codec is
// the thing under test here; verifying its output through its own reader would
// inherit whatever it got wrong.
func checkMergedDocumentLinks(mergedPath string, sources ...string) (checkInfo, error) {
	check := checkInfo{Name: "merged document links its sources"}
	wanted := map[string]struct{}{}
	for _, source := range sources {
		data, err := system.ReadFileLimit(source, maxDocumentBytes)
		if err != nil {
			return check, fmt.Errorf("read merge source: %w", err)
		}
		namespace, err := spdxNamespace(data)
		if err != nil {
			return check, fmt.Errorf("%s: %w", source, err)
		}
		wanted[namespace] = struct{}{}
	}
	data, err := system.ReadFileLimit(mergedPath, maxDocumentBytes)
	if err != nil {
		return check, fmt.Errorf("read merged document: %w", err)
	}
	verdict, err := evaluateMergedLinks(data, wanted)
	if err != nil {
		return check, fmt.Errorf("merged document: %w", err)
	}
	check.Passed, check.Detail = verdict.passed, verdict.detail
	return check, nil
}

type linkVerdict struct {
	passed bool
	detail string
}

// evaluateMergedLinks is the pure half of the link check, so it can be tested
// and fuzzed without generating documents.
func evaluateMergedLinks(merged []byte, wanted map[string]struct{}) (linkVerdict, error) {
	if len(merged) > maxDocumentBytes {
		return linkVerdict{}, fmt.Errorf("document is %d bytes, limit is %d", len(merged), maxDocumentBytes)
	}
	var document struct {
		SerialNumber       string `json:"serialNumber"`
		ExternalReferences []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"externalReferences"`
	}
	if err := json.Unmarshal(merged, &document); err != nil {
		return linkVerdict{}, fmt.Errorf("decode CycloneDX document: %w", err)
	}
	linked := map[string]struct{}{}
	for _, reference := range document.ExternalReferences {
		if reference.Type == "bom" {
			linked[reference.URL] = struct{}{}
		}
	}
	var missing []string
	for namespace := range wanted {
		if _, ok := linked[namespace]; !ok {
			missing = append(missing, namespace)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return linkVerdict{detail: "merged document does not link its sources: " + strings.Join(missing, ", ")}, nil
	}
	if _, adopted := wanted[document.SerialNumber]; adopted {
		return linkVerdict{detail: "merged document adopted a source's identity: " + document.SerialNumber}, nil
	}
	return linkVerdict{passed: true, detail: fmt.Sprintf("merged document links %d source(s)", len(linked))}, nil
}

func spdxNamespace(data []byte) (string, error) {
	if len(data) > maxDocumentBytes {
		return "", fmt.Errorf("document is %d bytes, limit is %d", len(data), maxDocumentBytes)
	}
	var document struct {
		DocumentNamespace string `json:"documentNamespace"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return "", fmt.Errorf("decode SPDX document: %w", err)
	}
	if document.DocumentNamespace == "" {
		return "", errors.New("SPDX document has no documentNamespace")
	}
	return document.DocumentNamespace, nil
}

func describeArtifact(format, path string) (artifactInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return artifactInfo{}, fmt.Errorf("read generated %s: %w", format, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return artifactInfo{}, fmt.Errorf("stat generated %s: %w", format, err)
	}
	sum := sha256.Sum256(data)
	return artifactInfo{
		Format: format, Path: path, SHA256: hex.EncodeToString(sum[:]), Bytes: info.Size(),
	}, nil
}

func writeFailure(outputDir string, manifest *runManifest, cause error) error {
	manifest.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	manifest.Failure = cause.Error()
	if err := writeManifest(outputDir, *manifest); err != nil {
		return fmt.Errorf("%v; additionally write run manifest: %w", cause, err)
	}
	return cause
}

func writeManifest(outputDir string, manifest runManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode run manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(outputDir, "run-manifest.json"), data, 0o600); err != nil {
		return fmt.Errorf("write run manifest: %w", err)
	}
	return nil
}
