// Command sbomassurance generates canonical SBOMs and validates them with
// checksum-pinned upstream tools. It is intended only for the explicit
// interoperability assurance workflow.
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
)

const (
	manifestSchema = "bomly.sbom-assurance-run/v1"

	spdxVersion  = "2.0.7"
	spdxURL      = "https://github.com/spdx/tools-java/releases/download/v2.0.7/tools-java-2.0.7.zip"
	spdxSHA256   = "2dc63c3399c5178058b1be8a3de6f13b9f24981cd86c4292ef98f4a7e90de36d"
	cdxVersion   = "0.32.0"
	cdxURL       = "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.32.0/cyclonedx-linux-x64"
	cdxSHA256    = "454879e6a4a405c8a13bff49b8982adcb0596f3019b26b0811c66e4d7f0783e1"
	defaultInput = "test/smoke/testdata/sboms/go.spdx.json"
)

type runManifest struct {
	SchemaVersion string          `json:"schema_version"`
	StartedAt     string          `json:"started_at"`
	FinishedAt    string          `json:"finished_at"`
	Host          hostInfo        `json:"host"`
	Validators    []validatorInfo `json:"validators"`
	Artifacts     []artifactInfo  `json:"artifacts"`
	Commands      []commandResult `json:"commands"`
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
	flag.Parse()

	if err := run(bomlyPath, outputDir, inputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(bomlyPath, outputDir, inputPath string) error {
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
		{name: "cyclonedx-1.6-json", path: filepath.Join(outputDir, "bomly.cdx.json")},
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

	commands := [][]string{
		{"java", "-jar", spdxJar, "Verify", formats[0].path},
		{cdxBinary, "validate", "--input-file", formats[1].path, "--input-format", "json", "--input-version", "v1_6", "--fail-on-errors"},
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
	var candidates []string
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() || !strings.HasSuffix(entry.Name, "-jar-with-dependencies.jar") {
			continue
		}
		candidates = append(candidates, entry.Name)
	}
	sort.Strings(candidates)
	if len(candidates) != 1 {
		return "", fmt.Errorf("SPDX validator archive contains %d executable jars", len(candidates))
	}
	entryPath := candidates[0]
	var source *zip.File
	for _, entry := range reader.File {
		if entry.Name == entryPath {
			source = entry
			break
		}
	}
	input, err := source.Open()
	if err != nil {
		return "", fmt.Errorf("open SPDX validator jar: %w", err)
	}
	defer input.Close()
	jarPath := filepath.Join(destination, filepath.Base(entryPath))
	output, err := os.OpenFile(jarPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create SPDX validator jar: %w", err)
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return "", fmt.Errorf("extract SPDX validator jar: %w", copyErr)
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
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
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
