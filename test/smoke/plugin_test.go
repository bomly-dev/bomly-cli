//go:build smoke

package smoke

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

func TestPluginWorkflows(t *testing.T) {
	requireTool(t, "go")

	parallelSubtest(t, "dev-install-scan", func(t *testing.T) {
		plugin := buildExamplePlugin(t)
		projectDir := createExamplePluginProject(t)
		env := pluginWorkflowEnv(t)

		stdout, stderr, code := runBomlyWithEnv(t, env, "plugin", "install", plugin.BinaryPath, "--dev")
		if code != 0 {
			t.Fatalf("plugin install --dev exited %d\nstderr:\n%s", code, stderr)
		}
		// A --dev install synthesizes the manifest from the plugin's runtime
		// gRPC descriptor (which carries no version), so the version is stamped
		// "0.0.0-dev" rather than the manifest version used by archive installs.
		if !strings.Contains(stdout, "Installed "+plugin.ID+"@0.0.0-dev") {
			t.Fatalf("unexpected install output:\n%s", stdout)
		}
		if _, enableStderr, enableCode := runBomlyWithEnv(t, env, "plugin", "enable", plugin.ID); enableCode != 0 {
			t.Fatalf("plugin enable exited %d\nstderr:\n%s", enableCode, enableStderr)
		}

		verifyStdout, verifyStderr, verifyCode := runBomlyWithEnv(t, env, "plugin", "verify", plugin.ID)
		if verifyCode != 0 {
			t.Fatalf("plugin verify exited %d\nstderr:\n%s", verifyCode, verifyStderr)
		}
		if !strings.Contains(verifyStdout, "[ok] runtime descriptor matches installed snapshot") {
			t.Fatalf("unexpected verify output:\n%s", verifyStdout)
		}

		listStdout, listStderr, listCode := runBomlyWithEnv(t, env, "plugin", "list", "--external", "--format", "json")
		if listCode != 0 {
			t.Fatalf("plugin list exited %d\nstderr:\n%s", listCode, listStderr)
		}
		assertPluginListed(t, listStdout, plugin.ID)

		infoStdout, infoStderr, infoCode := runBomlyWithEnv(t, env, "plugin", "info", plugin.ID, "--json")
		if infoCode != 0 {
			t.Fatalf("plugin info exited %d\nstderr:\n%s", infoCode, infoStderr)
		}
		assertPluginInfo(t, infoStdout, plugin.ID)

		scanStdout, scanStderr, scanCode := runBomlyWithEnv(t, env,
			"scan",
			"--path", projectDir,
			"--detectors", plugin.ID,
			"--format", "json",
		)
		if scanCode != 0 {
			t.Fatalf("plugin scan exited %d\nstderr:\n%s", scanCode, scanStderr)
		}
		assertGolden(t, "plugin-scan-dev", normalizeJSON(t, []byte(scanStdout)))
	})

	parallelSubtest(t, "archive-install-scan", func(t *testing.T) {
		plugin := buildExamplePlugin(t)
		archivePath := packageExamplePluginArchive(t, plugin)
		projectDir := createExamplePluginProject(t)
		env := pluginWorkflowEnv(t)

		stdout, stderr, code := runBomlyWithEnv(t, env, "plugin", "install", archivePath)
		if code != 0 {
			t.Fatalf("plugin install archive exited %d\nstderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, "Installed "+plugin.ID+"@"+plugin.Version) {
			t.Fatalf("unexpected archive install output:\n%s", stdout)
		}
		if _, enableStderr, enableCode := runBomlyWithEnv(t, env, "plugin", "enable", plugin.ID); enableCode != 0 {
			t.Fatalf("plugin enable exited %d\nstderr:\n%s", enableCode, enableStderr)
		}

		scanStdout, scanStderr, scanCode := runBomlyWithEnv(t, env,
			"scan",
			"--path", projectDir,
			"--detectors", plugin.ID,
			"--format", "json",
		)
		if scanCode != 0 {
			t.Fatalf("archive plugin scan exited %d\nstderr:\n%s", scanCode, scanStderr)
		}
		assertGolden(t, "plugin-scan-archive", normalizeJSON(t, []byte(scanStdout)))
	})
}

// TestAnalyzerPluginWorkflow exercises the managed analyzer plugin role end
// to end: dev-install the embedded analyzer fixture, enable it, confirm the
// plugin list groups it under analyzers with an external origin, run an
// --analyze scan on a local fixture project, and confirm the analyzer both
// ran (metadata.analyzer_runs) and annotated a vulnerability with a
// reachability result. The fixture appends its process ID to a pid file on
// every hook call, so the test also proves that one pooled subprocess served
// every RPC in the scan.
func TestAnalyzerPluginWorkflow(t *testing.T) {
	requireTool(t, "go")

	plugin := buildExampleAnalyzerPlugin(t)
	projectDir := createExamplePluginProject(t)
	env := pluginWorkflowEnv(t)

	stdout, stderr, code := runBomlyWithEnv(t, env, "plugin", "install", plugin.BinaryPath, "--dev")
	if code != 0 {
		t.Fatalf("analyzer plugin install --dev exited %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "Installed "+plugin.ID+"@0.0.0-dev") {
		t.Fatalf("unexpected analyzer install output:\n%s", stdout)
	}
	if _, enableStderr, enableCode := runBomlyWithEnv(t, env, "plugin", "enable", plugin.ID); enableCode != 0 {
		t.Fatalf("analyzer plugin enable exited %d\nstderr:\n%s", enableCode, enableStderr)
	}

	listStdout, listStderr, listCode := runBomlyWithEnv(t, env, "plugin", "list", "--external", "--format", "json")
	if listCode != 0 {
		t.Fatalf("plugin list exited %d\nstderr:\n%s", listCode, listStderr)
	}
	assertAnalyzerPluginListed(t, listStdout, plugin.ID)

	// The pid file arrives through the kind-scoped plugins.analyzers.<name>
	// config block, which the host serializes into the plugin subprocess
	// environment. Every fixture hook appends its PID to this file.
	pidFile := filepath.Join(t.TempDir(), "analyzer-pids.txt")
	configPath := filepath.Join(t.TempDir(), "bomly.yaml")
	configYAML := "plugins:\n  analyzers:\n    " + plugin.ID + ":\n      pid_file: " + pidFile + "\n"
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("write scan config: %v", err)
	}

	// --analyze requires --enrich. Keep enrichment hermetic by restricting
	// matchers to osv and pointing it at an unroutable local address: the
	// matcher degrades to a pipeline warning without touching the network,
	// and the analyzer stage still runs.
	scanEnv := append(append([]string(nil), env...), "BOMLY_OSV_API_BASE=http://127.0.0.1:1")
	scanStdout, scanStderr, scanCode := runBomlyWithEnv(t, scanEnv,
		"scan",
		"--path", projectDir,
		"--detectors", "go",
		"--enrich",
		"--matchers", "osv",
		"--analyze",
		"--analyzers", plugin.ID,
		"--config", configPath,
		"--format", "json",
	)
	if scanCode != 0 {
		t.Fatalf("analyzer plugin scan exited %d\nstderr:\n%s", scanCode, scanStderr)
	}
	assertAnalyzerRan(t, scanStdout, plugin.ID)
	if !strings.Contains(scanStdout, "EXAMPLE-REACH-0001") {
		t.Fatalf("scan output does not contain the analyzer's reachability-annotated vulnerability EXAMPLE-REACH-0001:\n%s", scanStdout)
	}
	assertSinglePluginSubprocess(t, pidFile)

	if _, disableStderr, disableCode := runBomlyWithEnv(t, env, "plugin", "disable", plugin.ID); disableCode != 0 {
		t.Fatalf("analyzer plugin disable exited %d\nstderr:\n%s", disableCode, disableStderr)
	}
	if _, uninstallStderr, uninstallCode := runBomlyWithEnv(t, env, "plugin", "uninstall", plugin.ID); uninstallCode != 0 {
		t.Fatalf("analyzer plugin uninstall exited %d\nstderr:\n%s", uninstallCode, uninstallStderr)
	}
}

// assertAnalyzerPluginListed decodes the grouped plugin list JSON and checks
// the plugin appears under the analyzers group with an external origin.
func assertAnalyzerPluginListed(t *testing.T, raw string, pluginID string) {
	t.Helper()
	var grouped map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &grouped); err != nil {
		t.Fatalf("decode plugin list output: %v\nraw:\n%s", err, raw)
	}
	var analyzers []map[string]any
	if err := json.Unmarshal(grouped["analyzers"], &analyzers); err != nil {
		t.Fatalf("decode analyzers group: %v\nraw:\n%s", err, raw)
	}
	for _, item := range analyzers {
		if item["id"] != pluginID {
			continue
		}
		if builtIn, _ := item["BuiltIn"].(bool); builtIn {
			t.Fatalf("analyzer plugin %q is listed as built-in; want external origin", pluginID)
		}
		if enabled, _ := item["Enabled"].(bool); !enabled {
			t.Fatalf("analyzer plugin %q is listed as disabled after enable", pluginID)
		}
		return
	}
	t.Fatalf("analyzer plugin %q was not listed under analyzers:\n%s", pluginID, raw)
}

// assertAnalyzerRan checks the scan response metadata records the analyzer
// in analyzer_runs.
func assertAnalyzerRan(t *testing.T, raw string, pluginID string) {
	t.Helper()
	var response struct {
		Metadata struct {
			AnalyzerRuns []string `json:"analyzer_runs"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatalf("decode scan output: %v", err)
	}
	for _, run := range response.Metadata.AnalyzerRuns {
		if run == pluginID {
			return
		}
	}
	t.Fatalf("analyzer %q not recorded in metadata.analyzer_runs %v", pluginID, response.Metadata.AnalyzerRuns)
}

// assertSinglePluginSubprocess reads the pid file the analyzer fixture
// appended to on every hook call and asserts every recorded PID is identical:
// one pooled subprocess served the whole scan.
func assertSinglePluginSubprocess(t *testing.T, pidFile string) {
	t.Helper()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read analyzer pid file: %v", err)
	}
	pids := strings.Fields(string(data))
	if len(pids) < 2 {
		t.Fatalf("expected at least 2 recorded plugin PIDs (Ready, Applicable, Analyze), got %d: %v", len(pids), pids)
	}
	for _, pid := range pids[1:] {
		if pid != pids[0] {
			t.Fatalf("analyzer plugin used more than one subprocess during the scan: %v", pids)
		}
	}
}

type examplePluginPackage struct {
	BinaryPath   string
	SourceDir    string
	ManifestPath string
	ReadmePath   string
	ID           string
	Version      string
}

func buildExamplePlugin(t *testing.T) examplePluginPackage {
	t.Helper()
	return buildExamplePluginWithSDK(t, sdkModuleVersion(t))
}

// buildExamplePluginWithSDK builds the example detector fixture against a
// specific github.com/bomly-dev/bomly-sdk release. The min-version
// wire-compatibility smoke uses it to compile against the oldest supported
// SDK release instead of the pinned one.
func buildExamplePluginWithSDK(t *testing.T, sdkVersion string) examplePluginPackage {
	t.Helper()
	// TODO: Replace this generated fixture with the public example plugin repos once they can be cloned in CI.
	binaryName := "bomly-example-gomod-detector"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	sourceDir := t.TempDir()
	writeExamplePluginSource(t, sourceDir, sdkVersion)
	manifestPath := filepath.Join(sourceDir, "bomly-plugin.json")
	readmePath := filepath.Join(sourceDir, "README.md")
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	build := exec.Command("go", "build", "-mod=mod", "-o", binaryPath, ".")
	build.Dir = sourceDir
	output, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build example plugin: %v\n%s", err, string(output))
	}
	return examplePluginPackage{
		BinaryPath:   binaryPath,
		SourceDir:    sourceDir,
		ManifestPath: manifestPath,
		ReadmePath:   readmePath,
		ID:           "bomly.example.gomod-detector",
		Version:      "0.1.0",
	}
}

func writeExamplePluginSource(t *testing.T, dir, sdkVersion string) {
	t.Helper()
	// The fixture source has to match the API of the SDK release it is built
	// against: the node constructors replaced sdk.NewDependency in v0.8.0, so
	// the min-version wire-compatibility build uses the legacy source.
	source := examplePluginMainSource
	if sdkVersion == minSupportedSDKVersion {
		source = legacyExamplePluginMainSource
	}
	goMod := "module bomly-smoke-plugin\n\ngo 1.25\n\nrequire github.com/bomly-dev/bomly-sdk " + sdkVersion + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write plugin go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o644); err != nil {
		t.Fatalf("write plugin main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bomly-plugin.json"), []byte(examplePluginManifest), 0o644); err != nil {
		t.Fatalf("write plugin manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Smoke Plugin Fixture\n\nGenerated by the smoke test.\n"), 0o644); err != nil {
		t.Fatalf("write plugin README: %v", err)
	}
}

// buildExampleAnalyzerPlugin builds the embedded example analyzer fixture
// (exampleAnalyzerPluginMainSource in fixture_compile_test.go) against the
// pinned sdk release and returns the built binary.
func buildExampleAnalyzerPlugin(t *testing.T) examplePluginPackage {
	t.Helper()
	binaryName := "bomly-example-reach-analyzer"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	sourceDir := t.TempDir()
	goMod := "module bomly-smoke-analyzer-plugin\n\ngo 1.25\n\nrequire github.com/bomly-dev/bomly-sdk " + sdkModuleVersion(t) + "\n"
	if err := os.WriteFile(filepath.Join(sourceDir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write analyzer plugin go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte(exampleAnalyzerPluginMainSource), 0o644); err != nil {
		t.Fatalf("write analyzer plugin main.go: %v", err)
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	build := exec.Command("go", "build", "-mod=mod", "-o", binaryPath, ".")
	build.Dir = sourceDir
	output, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build example analyzer plugin: %v\n%s", err, string(output))
	}
	return examplePluginPackage{
		BinaryPath: binaryPath,
		SourceDir:  sourceDir,
		ID:         "bomly.example.reach-analyzer",
		Version:    "0.0.0-dev",
	}
}

// examplePluginMainSource lives in the build-tag-free fixture_compile_test.go
// so it is compile-checked by `make test`; it is reused here for the
// end-to-end smoke workflow.

const examplePluginManifest = `{
  "schemaVersion": "bomly.plugin.package.v1",
  "id": "bomly.example.gomod-detector",
  "name": "Bomly Example Go Module Detector",
  "version": "0.1.0",
  "kind": "detector",
  "runtime": "hashicorp-grpc",
  "pluginApiVersion": "bomly.plugin.v1",
  "bomlyVersion": ">=0.1.0",
  "entrypoint": {
    "linux/amd64": "bin/bomly-example-gomod-detector",
    "darwin/arm64": "bin/bomly-example-gomod-detector",
    "windows/amd64": "bin/bomly-example-gomod-detector.exe"
  },
  "detectorDescriptor": {
    "name": "bomly.example.gomod-detector",
    "enabled": true,
    "origin": "external",
    "supportedModes": [
      "full-graph",
      "component"
    ],
    "packageManagerSupport": [
      {
        "packageManager": "gomod",
        "evidencePatterns": [
          "go.mod"
        ]
      }
    ],
    "capabilities": [
      "dependency-detection"
    ]
  },
  "source": "local:smoke-test",
  "homepage": "https://github.com/bomly-dev/bomly-plugin-bun-lock-detector",
  "license": "Apache-2.0",
  "description": "Example managed detector plugin that reads a local go.mod and returns the module itself as a single package."
}
`

func packageExamplePluginArchive(t *testing.T, plugin examplePluginPackage) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		archivePath := filepath.Join(t.TempDir(), "bomly-example-gomod-detector_windows_amd64.zip")
		file, err := os.Create(archivePath)
		if err != nil {
			t.Fatalf("create plugin zip: %v", err)
		}
		zw := zip.NewWriter(file)
		addZipFile(t, zw, "bomly-plugin.json", plugin.ManifestPath)
		addZipFile(t, zw, "README.md", plugin.ReadmePath)
		addZipFile(t, zw, "bin/"+filepath.Base(plugin.BinaryPath), plugin.BinaryPath)
		if err := zw.Close(); err != nil {
			t.Fatalf("close plugin zip: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close plugin zip file: %v", err)
		}
		return archivePath
	}

	archivePath := filepath.Join(t.TempDir(), "bomly-example-gomod-detector_"+runtime.GOOS+"_"+runtime.GOARCH+".tar.gz")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create plugin archive: %v", err)
	}
	gzw := gzip.NewWriter(file)
	tw := tar.NewWriter(gzw)
	addTarFile(t, tw, "bomly-plugin.json", plugin.ManifestPath)
	addTarFile(t, tw, "README.md", plugin.ReadmePath)
	addTarFile(t, tw, "bin/"+filepath.Base(plugin.BinaryPath), plugin.BinaryPath)
	if err := tw.Close(); err != nil {
		t.Fatalf("close plugin tar writer: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("close plugin gzip writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close plugin archive file: %v", err)
	}
	return archivePath
}

func addZipFile(t *testing.T, zw *zip.Writer, name, srcPath string) {
	t.Helper()
	writer, err := zw.Create(name)
	if err != nil {
		t.Fatalf("create zip entry %s: %v", name, err)
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read zip source %s: %v", srcPath, err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("write zip entry %s: %v", name, err)
	}
}

func addTarFile(t *testing.T, tw *tar.Writer, name, srcPath string) {
	t.Helper()
	info, err := os.Stat(srcPath)
	if err != nil {
		t.Fatalf("stat tar source %s: %v", srcPath, err)
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		t.Fatalf("build tar header %s: %v", srcPath, err)
	}
	header.Name = name
	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("write tar header %s: %v", name, err)
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read tar source %s: %v", srcPath, err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("write tar entry %s: %v", name, err)
	}
}

func createExamplePluginProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/plugin-smoke\n\ngo 1.25.0\n"), 0o644); err != nil {
		t.Fatalf("write example go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("write example main.go: %v", err)
	}
	return dir
}

func assertPluginListed(t *testing.T, raw string, pluginID string) {
	t.Helper()
	var items []map[string]any
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		var grouped map[string][]map[string]any
		if groupedErr := json.Unmarshal([]byte(raw), &grouped); groupedErr != nil {
			t.Fatalf("decode plugin list output: %v; grouped decode: %v\nraw:\n%s", err, groupedErr, raw)
		}
		for _, group := range grouped {
			items = append(items, group...)
		}
	}
	for _, item := range items {
		if item["id"] == pluginID {
			return
		}
	}
	t.Fatalf("plugin %q was not listed in plugin list output", pluginID)
}

func assertPluginInfo(t *testing.T, raw string, pluginID string) {
	t.Helper()
	var item map[string]any
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		t.Fatalf("decode plugin info output: %v\nraw:\n%s", err, raw)
	}
	if item["id"] != pluginID {
		t.Fatalf("expected plugin info id %q, got %#v", pluginID, item["id"])
	}
}

func pluginWorkflowEnv(t *testing.T) []string {
	t.Helper()
	return []string{"BOMLY_PLUGIN_HOME=" + filepath.Join(t.TempDir(), "plugins")}
}
