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
)

func TestPluginWorkflows(t *testing.T) {
	requireTool(t, "go")

	parallelSubtest(t, "dev-install-scan", func(t *testing.T) {
		binaryPath, manifest := buildExamplePlugin(t)
		projectDir := createExamplePluginProject(t)
		env := pluginWorkflowEnv(t)

		stdout, stderr, code := runBomlyWithEnv(t, env, "plugin", "install", binaryPath, "--dev")
		if code != 0 {
			t.Fatalf("plugin install --dev exited %d\nstderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, "Installed "+manifest["id"].(string)+"@"+manifest["version"].(string)) {
			t.Fatalf("unexpected install output:\n%s", stdout)
		}
		if _, enableStderr, enableCode := runBomlyWithEnv(t, env, "plugin", "enable", manifest["id"].(string)); enableCode != 0 {
			t.Fatalf("plugin enable exited %d\nstderr:\n%s", enableCode, enableStderr)
		}

		verifyStdout, verifyStderr, verifyCode := runBomlyWithEnv(t, env, "plugin", "verify", manifest["id"].(string))
		if verifyCode != 0 {
			t.Fatalf("plugin verify exited %d\nstderr:\n%s", verifyCode, verifyStderr)
		}
		if !strings.Contains(verifyStdout, "[ok] runtime metadata matches manifest") {
			t.Fatalf("unexpected verify output:\n%s", verifyStdout)
		}

		listStdout, listStderr, listCode := runBomlyWithEnv(t, env, "plugin", "list", "--external", "--format", "json")
		if listCode != 0 {
			t.Fatalf("plugin list exited %d\nstderr:\n%s", listCode, listStderr)
		}
		assertPluginListed(t, listStdout, manifest["id"].(string))

		infoStdout, infoStderr, infoCode := runBomlyWithEnv(t, env, "plugin", "info", manifest["id"].(string), "--json")
		if infoCode != 0 {
			t.Fatalf("plugin info exited %d\nstderr:\n%s", infoCode, infoStderr)
		}
		assertPluginInfo(t, infoStdout, manifest["id"].(string))

		scanStdout, scanStderr, scanCode := runBomlyWithEnv(t, env,
			"scan",
			"--path", projectDir,
			"--detectors", manifest["id"].(string),
			"--format", "json",
		)
		if scanCode != 0 {
			t.Fatalf("plugin scan exited %d\nstderr:\n%s", scanCode, scanStderr)
		}
		assertGolden(t, "plugin-scan-dev", normalizeJSON(t, []byte(scanStdout)))
	})

	parallelSubtest(t, "archive-install-scan", func(t *testing.T) {
		binaryPath, manifest := buildExamplePlugin(t)
		archivePath := packageExamplePluginArchive(t, binaryPath)
		projectDir := createExamplePluginProject(t)
		pluginID := manifest["id"].(string)
		env := pluginWorkflowEnv(t)

		stdout, stderr, code := runBomlyWithEnv(t, env, "plugin", "install", archivePath)
		if code != 0 {
			t.Fatalf("plugin install archive exited %d\nstderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, "Installed "+pluginID+"@"+manifest["version"].(string)) {
			t.Fatalf("unexpected archive install output:\n%s", stdout)
		}
		if _, enableStderr, enableCode := runBomlyWithEnv(t, env, "plugin", "enable", pluginID); enableCode != 0 {
			t.Fatalf("plugin enable exited %d\nstderr:\n%s", enableCode, enableStderr)
		}

		scanStdout, scanStderr, scanCode := runBomlyWithEnv(t, env,
			"scan",
			"--path", projectDir,
			"--detectors", pluginID,
			"--format", "json",
		)
		if scanCode != 0 {
			t.Fatalf("archive plugin scan exited %d\nstderr:\n%s", scanCode, scanStderr)
		}
		assertGolden(t, "plugin-scan-archive", normalizeJSON(t, []byte(scanStdout)))
	})
}

func buildExamplePlugin(t *testing.T) (string, map[string]any) {
	t.Helper()
	exampleDir := filepath.Join(repoRoot(t), "examples", "plugins", "go-module-detector")
	manifestPath := filepath.Join(exampleDir, "bomly-plugin.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read example plugin manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode example plugin manifest: %v", err)
	}
	binaryName := "bomly-example-gomod-detector"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	build := exec.Command("go", "build", "-o", binaryPath, "./examples/plugins/go-module-detector")
	build.Dir = repoRoot(t)
	output, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build example plugin: %v\n%s", err, string(output))
	}
	return binaryPath, manifest
}

func packageExamplePluginArchive(t *testing.T, binaryPath string) string {
	t.Helper()
	exampleDir := filepath.Join(repoRoot(t), "examples", "plugins", "go-module-detector")
	manifestPath := filepath.Join(exampleDir, "bomly-plugin.json")
	readmePath := filepath.Join(exampleDir, "README.md")

	if runtime.GOOS == "windows" {
		archivePath := filepath.Join(t.TempDir(), "bomly-example-gomod-detector_windows_amd64.zip")
		file, err := os.Create(archivePath)
		if err != nil {
			t.Fatalf("create plugin zip: %v", err)
		}
		zw := zip.NewWriter(file)
		addZipFile(t, zw, "bomly-plugin.json", manifestPath)
		addZipFile(t, zw, "README.md", readmePath)
		addZipFile(t, zw, "bin/"+filepath.Base(binaryPath), binaryPath)
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
	addTarFile(t, tw, "bomly-plugin.json", manifestPath)
	addTarFile(t, tw, "README.md", readmePath)
	addTarFile(t, tw, "bin/"+filepath.Base(binaryPath), binaryPath)
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
