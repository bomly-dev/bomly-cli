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
		plugin := buildExamplePlugin(t)
		projectDir := createExamplePluginProject(t)
		env := pluginWorkflowEnv(t)

		stdout, stderr, code := runBomlyWithEnv(t, env, "plugin", "install", plugin.BinaryPath, "--dev")
		if code != 0 {
			t.Fatalf("plugin install --dev exited %d\nstderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, "Installed "+plugin.ID+"@"+plugin.Version) {
			t.Fatalf("unexpected install output:\n%s", stdout)
		}
		if _, enableStderr, enableCode := runBomlyWithEnv(t, env, "plugin", "enable", plugin.ID); enableCode != 0 {
			t.Fatalf("plugin enable exited %d\nstderr:\n%s", enableCode, enableStderr)
		}

		verifyStdout, verifyStderr, verifyCode := runBomlyWithEnv(t, env, "plugin", "verify", plugin.ID)
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
	// TODO: Replace this generated fixture with the public example plugin repos once they can be cloned in CI.
	binaryName := "bomly-example-gomod-detector"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	sourceDir := t.TempDir()
	writeExamplePluginSource(t, sourceDir)
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

func writeExamplePluginSource(t *testing.T, dir string) {
	t.Helper()
	// TODO: Use the real external detector example when the private plugin repos become public.
	repoPath := filepath.ToSlash(repoRoot(t))
	goMod := "module bomly-smoke-plugin\n\ngo 1.25\n\nrequire github.com/bomly-dev/bomly-cli v0.0.0\n\nreplace github.com/bomly-dev/bomly-cli => " + repoPath + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write plugin go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(examplePluginMainSource), 0o644); err != nil {
		t.Fatalf("write plugin main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bomly-plugin.json"), []byte(examplePluginManifest), 0o644); err != nil {
		t.Fatalf("write plugin manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Smoke Plugin Fixture\n\nGenerated by the smoke test.\n"), 0o644); err != nil {
		t.Fatalf("write plugin README: %v", err)
	}
}

const examplePluginMainSource = `package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const pluginID = "bomly.example.gomod-detector"

type detector struct{}

func (d *detector) Descriptor(context.Context) (*sdk.DetectorDescriptor, error) {
	return &sdk.DetectorDescriptor{
		Name: pluginID,
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]sdk.PackageManagerSupport, error) {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerGoMod, "go.mod")}, nil
}

func (d *detector) Ready(context.Context, *sdk.DetectRequest) (*sdk.ReadyResponse, error) {
	return &sdk.ReadyResponse{Ready: true}, nil
}

func (d *detector) Applicable(context.Context, *sdk.DetectRequest) (*sdk.ApplicableResponse, error) {
	return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(ctx context.Context, req *sdk.DetectRequest) (*sdk.DetectResponse, error) {
	moduleName, err := readModuleName(filepath.Join(req.ProjectPath, "go.mod"))
	if err != nil {
		return nil, err
	}
	pkg := sdk.NewDependency(sdk.Dependency{
		Ecosystem: string(sdk.EcosystemGo),
		Name:      moduleName,
		Version:   "v0.0.0",
		PURL:      "pkg:golang/" + moduleName + "@v0.0.0",
		FoundBy:   pluginID,
	})
	graph := sdk.New()
	if err := graph.AddNode(pkg); err != nil {
		return nil, err
	}
	return &sdk.DetectResponse{
		SubprojectInfo:      req.Subproject,
		RootExecutionTarget: req.ExecutionTarget,
		DetectorName:        pluginID,
		Origin:              sdk.ExternalOrigin,
		Graphs: &sdk.GraphContainer{
			Entries: []sdk.GraphEntry{{
				Manifest: sdk.ManifestMetadata{
					Path: filepath.Join(req.ProjectPath, "go.mod"),
					Kind: sdk.ManifestKind("go.mod"),
				},
				Graph: graph,
			}},
		},
	}, nil
}

func readModuleName(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "module ") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(line, "module"))
		if name == "" {
			return "", fmt.Errorf("go.mod module directive is empty")
		}
		return name, nil
	}
	return "", fmt.Errorf("go.mod does not contain a module directive")
}

func main() {
	sdk.ServeDetector(&detector{})
}
`

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
