package python

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	logging "github.com/bomly-dev/bomly-sdk/logkit"
	testutil "github.com/bomly-dev/bomly-sdk/testkit"
)

const fakePythonSource = `package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	args := os.Args[1:]
	if len(args) >= 3 && args[0] == "-m" && args[1] == "venv" {
		target := filepath.Join(args[2], "bin", "python")
		if runtime.GOOS == "windows" {
			target = filepath.Join(args[2], "Scripts", "python.exe")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			panic(err)
		}
		self, err := os.Executable()
		if err != nil {
			panic(err)
		}
		raw, err := os.ReadFile(self)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(target, raw, 0o755); err != nil {
			panic(err)
		}
		return
	}
	if len(args) >= 3 && args[0] == "-m" && args[1] == "pip" && args[2] == "--version" {
		version := os.Getenv("BOMLY_FAKE_PIP_VERSION")
		if version == "" {
			version = "24.0"
		}
		fmt.Printf("pip %s from /fake/pip (python 3.12)\n", version)
		return
	}
	if len(args) >= 3 && args[0] == "-m" && args[1] == "pip" && args[2] == "install" {
		if logPath := os.Getenv("BOMLY_FAKE_PYTHON_INSTALL_LOG"); logPath != "" {
			_ = os.WriteFile(logPath, []byte(strings.Join(args, " ")), 0o644)
		}
		return
	}
	if len(args) >= 3 && args[0] == "-m" && args[1] == "pip" && args[2] == "inspect" {
		if strings.Contains(os.Args[0], "bomly-pyvenv-") {
			fmt.Print(os.Getenv("BOMLY_FAKE_VENV_INSPECT"))
			return
		}
		fmt.Print(os.Getenv("BOMLY_FAKE_AMBIENT_INSPECT"))
		return
	}
	panic("unexpected fake python command: " + strings.Join(os.Args, " "))
}
`

const ambientPipAuditInspect = `{
  "installed": [
    {"metadata": {"name": "pip-audit", "version": "2.9.0", "requires_dist": ["CacheControl"]}, "requested": true},
    {"metadata": {"name": "CacheControl", "version": "0.14.0", "requires_dist": []}, "requested": false, "requested_by": ["pip-audit"]}
  ]
}`

const projectRequirementsInspect = `{
  "installed": [
    {"metadata": {"name": "fastapi", "version": "0.139.0", "requires_dist": ["urllib3"]}, "requested": true},
    {"metadata": {"name": "PyJWT", "version": "1.7.1", "requires_dist": []}, "requested": true},
    {"metadata": {"name": "ecdsa", "version": "0.19.2", "requires_dist": []}, "requested": true},
    {"metadata": {"name": "urllib3", "version": "1.26.5", "requires_dist": []}, "requested": true}
  ]
}`

func TestPipDetectorDoesNotReturnAmbientPipAuditEnvironment(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "requirements.txt"), []byte("fastapi==0.139.0\nPyJWT==1.7.1\necdsa==0.19.2\nurllib3==1.26.5\n"), 0o644); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}
	logs := setupFakePython(t, ambientPipAuditInspect, projectRequirementsInspect)
	t.Cleanup(func() { _ = os.RemoveAll(pythonVenvDir(projectDir)) })

	result, err := (PipDetector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	graph, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	for _, want := range []string{"fastapi@0.139.0", "pyjwt@1.7.1", "ecdsa@0.19.2", "urllib3@1.26.5"} {
		if _, ok := graph.Node(want); !ok {
			t.Fatalf("expected project dependency %s in graph: %s", want, graph.PrettyString())
		}
	}
	if _, ok := graph.Node("pip-audit@2.9.0"); ok {
		t.Fatalf("ambient pip-audit dependency leaked into project graph: %s", graph.PrettyString())
	}
	if raw, err := os.ReadFile(logs.install); err != nil || !strings.Contains(string(raw), "pip install -r requirements.txt") {
		t.Fatalf("expected isolated pip install to run, log=%q err=%v", string(raw), err)
	}
	resolution := result.Graphs.Entries[0].Manifest.Resolution
	if resolution == nil || resolution.Method != sdk.ResolutionMethodIsolatedInstall || !resolution.InstallExecuted {
		t.Fatalf("unexpected resolution metadata: %#v", resolution)
	}
}

func TestSanitizeCommandRedactsCredentials(t *testing.T) {
	got := logging.SanitizeArgs([]string{"python", "-m", "pip", "install", "--password", "secret", "--index-url=https://user:token@example.com/simple"})
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "secret") || strings.Contains(joined, "token") {
		t.Fatalf("credentials were not redacted: %v", got)
	}
	if !strings.Contains(joined, "[REDACTED]") {
		t.Fatalf("expected redaction marker in %v", got)
	}
}

func TestPythonLockfileResultsIncludeResolutionMetadata(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	tests := []struct {
		name     string
		detector sdk.Detector
		fixture  string
		method   sdk.ResolutionMethod
	}{
		{name: "pip", detector: PipDetector{}, fixture: pyFixture("pip"), method: sdk.ResolutionMethodLockfile},
		{name: "pipenv", detector: PipenvDetector{}, fixture: pyFixture("pipenv"), method: sdk.ResolutionMethodManifestOnly},
		{name: "poetry", detector: PoetryDetector{}, fixture: pyFixture("poetry"), method: sdk.ResolutionMethodLockfile},
		{name: "uv", detector: UVDetector{}, fixture: pyFixture("uv"), method: sdk.ResolutionMethodLockfile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.detector.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: tt.fixture})
			if err != nil {
				t.Fatalf("ResolveGraph() error = %v", err)
			}
			resolution := result.Graphs.Entries[0].Manifest.Resolution
			if resolution == nil || resolution.Method != tt.method {
				t.Fatalf("resolution method = %#v, want %q", resolution, tt.method)
			}
			if resolution.InstallExecuted {
				t.Fatalf("lockfile/manifest-only result reported an install execution: %#v", resolution)
			}
			if len(resolution.InstallCommand) > 0 || resolution.InstallWorkingDir != "" {
				t.Fatalf("lockfile/manifest-only result included install details: %#v", resolution)
			}
		})
	}
}

func TestPoetryAndUVFailWithoutLockfile(t *testing.T) {
	for _, detector := range []sdk.Detector{PoetryDetector{}, UVDetector{}} {
		projectDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte("[project]\nname = \"demo\"\ndependencies = [\"requests==2.32.3\"]\n"), 0o644); err != nil {
			t.Fatalf("write pyproject.toml: %v", err)
		}
		_, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
		if err == nil {
			t.Fatalf("%T unexpectedly resolved without a lockfile", detector)
		}
	}
}

// fakePythonLogs records where the fake interpreter writes the commands it was
// asked to run, so tests can assert which install steps actually happened.
type fakePythonLogs struct {
	install string
}

func setupFakePython(t *testing.T, ambientInspect, venvInspect string) fakePythonLogs {
	t.Helper()
	binDir := t.TempDir()
	binaryName := "python"
	if runtime.GOOS == "windows" {
		binaryName = "python.exe"
	}
	if err := testutil.BuildGoBinary(t, filepath.Join(binDir, binaryName), fakePythonSource); err != nil {
		t.Fatalf("build fake python: %v", err)
	}
	logs := fakePythonLogs{install: filepath.Join(t.TempDir(), "install.log")}
	t.Setenv("PATH", binDir)
	t.Setenv("BOMLY_FAKE_AMBIENT_INSPECT", ambientInspect)
	t.Setenv("BOMLY_FAKE_VENV_INSPECT", venvInspect)
	t.Setenv("BOMLY_FAKE_PYTHON_INSTALL_LOG", logs.install)
	return logs
}

// TestPipDetectorReportsUnsupportedPipVersion covers issue #274: `pip inspect`
// landed in pip 22.2, and a venv seeded from an old ambient interpreter
// (macOS system Python 3.9 ships pip 21.x) inherits its pip. Bomly diagnoses
// that instead of installing anything, so the failure must name the version
// and the requirement rather than surfacing a bare "exit status 1".
func TestPipDetectorReportsUnsupportedPipVersion(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "requirements.txt"), []byte("fastapi==0.139.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}
	logs := setupFakePython(t, ambientPipAuditInspect, projectRequirementsInspect)
	t.Setenv("BOMLY_FAKE_PIP_VERSION", "21.2.4")
	t.Cleanup(func() { _ = os.RemoveAll(pythonVenvDir(projectDir)) })

	_, err := (PipDetector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err == nil {
		t.Fatal("expected ResolveGraph to fail on a pip too old for `pip inspect`")
	}
	for _, want := range []string{"21.2.4", "22.2", "pip inspect"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
	// The environment is diagnosed before anything is installed: Bomly never
	// installs or upgrades a package manager, and a doomed resolution should
	// not spend a network round trip first.
	if raw, err := os.ReadFile(logs.install); err == nil {
		t.Fatalf("expected no install to run for an uninspectable environment, got %q", string(raw))
	}
}

func TestPipSupportsInspect(t *testing.T) {
	tests := map[string]bool{
		"21.2.4":     false,
		"22.1.2":     false,
		"22.2":       true,
		"22.3.1":     true,
		"25.1.1":     true,
		"":           true,
		"weird-fork": true,
	}
	for version, want := range tests {
		if got := pipSupportsInspect(version); got != want {
			t.Errorf("pipSupportsInspect(%q) = %v, want %v", version, got, want)
		}
	}
}
