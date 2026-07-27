package opts

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func TestCommandContextRoundTripsThroughContext(t *testing.T) {
	commandCtx := &Options{ResolvedConfig: config.Resolved{Path: "fixture"}}
	parent := context.Background()

	got, ok := FromContext(ToContext(parent, commandCtx))
	if !ok {
		t.Fatal("expected command context in context")
	}
	if got != commandCtx {
		t.Fatal("expected stored command context pointer")
	}
}

func TestPipelineRequestExposesSubprocessStderrOnlyAtDebug(t *testing.T) {
	var stderr bytes.Buffer

	infoOptions := Options{verbose: false}
	info := infoOptions.PipelineRequest(sdk.ScopeUnknown, &stderr)
	if info.Stderr != nil || info.Verbose {
		t.Fatalf("info request enabled subprocess stderr: %#v", info)
	}

	debugOptions := Options{verbose: true}
	debug := debugOptions.PipelineRequest(sdk.ScopeUnknown, &stderr)
	if debug.Stderr != &stderr || !debug.Verbose {
		t.Fatalf("debug request did not enable subprocess stderr: %#v", debug)
	}
}

func TestCommandContextResolveExecutionTarget_Image(t *testing.T) {
	options := Options{ResolvedConfig: config.Resolved{Image: "alpine:3.20"}}

	target, location, cleanup, err := options.resolveExecutionTarget(context.Background(), nil)
	if err != nil {
		t.Fatalf("resolveExecutionTarget() error = %v", err)
	}
	if cleanup != nil {
		t.Fatal("expected no cleanup for image target")
	}
	if target.Kind != sdk.ExecutionTargetContainerImage {
		t.Fatalf("expected container execution target, got %#v", target)
	}
	if target.Location != "alpine:3.20" || location != "alpine:3.20" {
		t.Fatalf("unexpected image target values: %#v %q", target, location)
	}
}

func TestProjectDescriptor_UsesUserFacingTargetLabels(t *testing.T) {
	containerOptions := Options{executionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetContainerImage, Location: "example/demo:1.0"}}
	containerProject := containerOptions.ProjectDescriptor()
	if containerProject.Name != "example/demo:1.0" || containerProject.Path != "example/demo:1.0" || containerProject.TargetType != "container image" {
		t.Fatalf("unexpected container project descriptor: %#v", containerProject)
	}

	// Git repositories name themselves after the repo (last URL segment,
	// .git trimmed); the full URL remains the descriptor's Path.
	urlOptions := Options{executionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetGitRepository, Location: `C:\Temp\bomly-clone`, RepositoryURL: "https://github.com/acme/demo.git", Ref: "main"}}
	urlProject := urlOptions.ProjectDescriptor()
	if urlProject.Name != "demo" || urlProject.Path != "https://github.com/acme/demo.git" || urlProject.TargetType != "git repository" || urlProject.TargetRef != "main" {
		t.Fatalf("unexpected url project descriptor: %#v", urlProject)
	}
}

func TestCommandContextResolveExecutionTarget_RejectsMultipleTargets(t *testing.T) {
	options := Options{ResolvedConfig: config.Resolved{Path: ".", Image: "alpine:3.20"}}

	_, _, _, err := options.resolveExecutionTarget(context.Background(), nil)
	if err == nil {
		t.Fatal("expected multiple target error")
	}
	if !strings.Contains(err.Error(), "--path, --url, and --image cannot be used together") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrepareForExecutionTargetLoadsBaselineOnlyForAudit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{\"name\":\"demo\",\"version\":\"1.0.0\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".bomly"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".bomly", "baseline.json"), []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Resolved{Baseline: "auto", Detectors: "npm"}
	config.ApplyDefaults(&cfg)
	options := Options{ResolvedConfig: cfg}
	target := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root}
	if _, err := options.PrepareForExecutionTarget(context.Background(), zap.NewNop(), target, nil); err != nil {
		t.Fatalf("non-audit preparation loaded baseline: %v", err)
	}
	cfg.Audit = true
	options.ResolvedConfig = cfg
	if _, err := options.PrepareForExecutionTarget(context.Background(), zap.NewNop(), target, nil); err == nil {
		t.Fatal("audit preparation should reject malformed automatic baseline")
	}
}

func TestAvailableFlagOptions_AreDerivedFromRegistry(t *testing.T) {
	ecosystems := availableEcosystemOptions()
	for _, want := range []string{"go", "maven", "npm", "python", "php", "rust", "terraform"} {
		if !containsOption(ecosystems, want) {
			t.Fatalf("expected ecosystem option %q in %#v", want, ecosystems)
		}
	}

	detectors := availableDetectorOptions()
	for _, want := range []string{
		"go-detector",
		"gradle-detector",
		"maven-detector",
		"npm-detector",
		"pip-detector",
		"pipenv-detector",
		"pnpm-detector",
		"poetry-detector",
		"syft-detector",
		"uv-detector",
		"yarn-detector",
	} {
		if !containsOption(detectors, want) {
			t.Fatalf("expected detector option %q in %#v", want, detectors)
		}
	}
}

func TestDetectPackageManagers_FindsPythonManagers(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "requirements.txt"), []byte("requests==2.32.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "Pipfile"), []byte("[packages]\nrequests = \"*\"\n"), 0o644); err != nil {
		t.Fatalf("write Pipfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "poetry.lock"), []byte("# lock\n"), 0o644); err != nil {
		t.Fatalf("write poetry.lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "uv.lock"), []byte("version = 1\n"), 0o644); err != nil {
		t.Fatalf("write uv.lock: %v", err)
	}

	managers, err := registry.DetectPackageManagers(projectDir)
	if err != nil {
		t.Fatalf("DetectPackageManagers() error = %v", err)
	}

	for _, want := range []sdk.PackageManager{
		sdk.PackageManagerPip,
		sdk.PackageManagerPipenv,
		sdk.PackageManagerPoetry,
		sdk.PackageManagerUV,
	} {
		if !containsManager(managers, want) {
			t.Fatalf("expected package manager %q in %#v", want, managers)
		}
	}
}

func TestDetectPackageManagers_UsesPyprojectToolTables(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    sdk.PackageManager
		block   sdk.PackageManager
	}{
		{
			name:    "uv",
			content: "[project]\nname = \"demo\"\n\n[tool.uv]\ndev-dependencies = []\n",
			want:    sdk.PackageManagerUV,
			block:   sdk.PackageManagerPoetry,
		},
		{
			name:    "poetry",
			content: "[tool.poetry]\nname = \"demo\"\nversion = \"1.0.0\"\n",
			want:    sdk.PackageManagerPoetry,
			block:   sdk.PackageManagerUV,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			projectDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(tc.content), 0o644); err != nil {
				t.Fatalf("write pyproject.toml: %v", err)
			}

			managers, err := registry.DetectPackageManagers(projectDir)
			if err != nil {
				t.Fatalf("DetectPackageManagers() error = %v", err)
			}
			if !containsManager(managers, tc.want) {
				t.Fatalf("expected package manager %q in %#v", tc.want, managers)
			}
			if containsManager(managers, tc.block) {
				t.Fatalf("did not expect package manager %q in %#v", tc.block, managers)
			}
		})
	}
}

func TestDetectPackageManagers_PrefersSpecificEvidence(t *testing.T) {
	tests := []struct {
		name   string
		files  map[string]string
		want   sdk.PackageManager
		reject []sdk.PackageManager
	}{
		{
			name: "uv lock beats pyproject",
			files: map[string]string{
				"pyproject.toml": "[project]\nname = \"demo\"\n",
				"uv.lock":        "version = 1\n",
			},
			want:   sdk.PackageManagerUV,
			reject: []sdk.PackageManager{sdk.PackageManagerPoetry},
		},
		{
			name: "poetry lock beats pyproject",
			files: map[string]string{
				"pyproject.toml": "[project]\nname = \"demo\"\n",
				"poetry.lock":    "# lock\n",
			},
			want:   sdk.PackageManagerPoetry,
			reject: []sdk.PackageManager{sdk.PackageManagerUV},
		},
		{
			name: "pnpm lock beats package json",
			files: map[string]string{
				"package.json":   "{}\n",
				"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
			},
			want:   sdk.PackageManagerPNPM,
			reject: []sdk.PackageManager{sdk.PackageManagerNPM, sdk.PackageManagerYarn},
		},
		{
			name: "yarn lock beats package json",
			files: map[string]string{
				"package.json": "{}\n",
				"yarn.lock":    "# yarn lock\n",
			},
			want:   sdk.PackageManagerYarn,
			reject: []sdk.PackageManager{sdk.PackageManagerNPM, sdk.PackageManagerPNPM},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			projectDir := t.TempDir()
			for name, content := range tc.files {
				if err := os.WriteFile(filepath.Join(projectDir, name), []byte(content), 0o644); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
			}

			managers, err := registry.DetectPackageManagers(projectDir)
			if err != nil {
				t.Fatalf("DetectPackageManagers() error = %v", err)
			}
			if !containsManager(managers, tc.want) {
				t.Fatalf("expected package manager %q in %#v", tc.want, managers)
			}
			for _, reject := range tc.reject {
				if containsManager(managers, reject) {
					t.Fatalf("did not expect package manager %q in %#v", reject, managers)
				}
			}
		})
	}
}

func TestDetectPackageManagers_FindsSyftManagers(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "Cargo.lock"), []byte("version = 3\n"), 0o644); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".terraform.lock.hcl"), []byte("# lock\n"), 0o644); err != nil {
		t.Fatalf("write .terraform.lock.hcl: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "composer.lock"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write composer.lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "pdm.lock"), []byte("[metadata]\n"), 0o644); err != nil {
		t.Fatalf("write pdm.lock: %v", err)
	}

	managers, err := registry.DetectPackageManagers(projectDir)
	if err != nil {
		t.Fatalf("DetectPackageManagers() error = %v", err)
	}

	for _, want := range []sdk.PackageManager{
		sdk.PackageManagerCargo,
		sdk.PackageManagerTerraform,
		sdk.PackageManagerComposer,
		sdk.PackageManagerPDM,
	} {
		if !containsManager(managers, want) {
			t.Fatalf("expected package manager %q in %#v", want, managers)
		}
	}
}

func TestCommandContextBind_AnnotatesUsageWithAvailableOptions(t *testing.T) {
	options := &Options{}
	root := newTestRootCommand(t)

	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}

	for _, flagName := range []string{"config", "quiet", "verbose"} {
		flag := root.PersistentFlags().Lookup(flagName)
		if flag == nil {
			t.Fatalf("expected flag %q to exist", flagName)
		}
	}
	for _, flagName := range []string{"ecosystems", "detectors", "auditors", "matchers"} {
		if flag := root.PersistentFlags().Lookup(flagName); flag != nil {
			t.Fatalf("expected non-global flag %q to be command-scoped", flagName)
		}
	}
}

func TestCSVCompletionFunc_CompletesCommaSeparatedValues(t *testing.T) {
	completion := csvCompletionFunc([]string{"npm", "maven", "python"})
	got, directive := completion(nil, nil, "npm,m")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("expected no-file completion directive, got %v", directive)
	}
	if len(got) != 1 || got[0] != "npm,maven" {
		t.Fatalf("unexpected completion values: %#v", got)
	}
}

func TestCommandContextInitialize_LoadsUserAndExplicitConfig(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	projectDir := t.TempDir()
	t.Chdir(projectDir)

	if err := os.MkdirAll(filepath.Join(tempHome, ".bomly"), 0o755); err != nil {
		t.Fatalf("mkdir home config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(tempHome, ".bomly", "config.yaml"), map[string]any{
		"components": map[string]any{
			"ecosystems": "npm",
			"detectors":  "syft-detector",
		},
		"logging": map[string]any{
			"verbosity": 1,
		},
	})

	if err := os.MkdirAll(filepath.Join(projectDir, ".bomly"), 0o755); err != nil {
		t.Fatalf("mkdir project config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(projectDir, ".bomly", "config.yaml"), map[string]any{
		"components": map[string]any{
			"ecosystems": "go",
			"detectors":  "go-detector",
		},
	})

	explicitConfig := filepath.Join(t.TempDir(), "bomly.yaml")
	writeConfigFile(t, explicitConfig, map[string]any{
		"components": map[string]any{
			"detectors": "maven-detector",
		},
	})

	options := &Options{
		ResolvedConfig: config.Resolved{
			Config:     explicitConfig,
			Ecosystems: "python",
		},
	}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupSelectors); err != nil {
		t.Fatalf("BindCommandFlagGroups() error = %v", err)
	}
	root.SetArgs([]string{"--config", explicitConfig, "--ecosystems", "python"})
	if err := root.ParseFlags(root.Flags().Args()); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--config", explicitConfig, "--ecosystems", "python"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("initialize() error = %v", err)
	}

	got := options.GetConfig()
	if got.Ecosystems != "python" {
		t.Fatalf("expected flag ecosystems override, got %q", got.Ecosystems)
	}
	if got.Detectors != "maven-detector" {
		t.Fatalf("expected explicit config detectors override, got %q", got.Detectors)
	}
	if got.Verbosity == 0 {
		t.Fatal("expected verbosity value from home config")
	}
	if len(got.LoadedFiles) != 2 {
		t.Fatalf("expected user and explicit config files, got %#v", got.LoadedFiles)
	}
	for _, loaded := range got.LoadedFiles {
		if loaded == filepath.Join(projectDir, ".bomly", "config.yaml") {
			t.Fatalf("automatically loaded repository config %q", loaded)
		}
	}
}

func TestCommandContextInitialize_AppliesConfigPrecedence(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)
	t.Setenv("BOMLY_FAIL_ON", "critical")
	t.Setenv("BOMLY_FORMAT", "sarif")
	t.Setenv("BOMLY_ECOSYSTEMS", "npm")
	t.Setenv("BOMLY_OSV_CACHE_TTL", "3h")

	projectDir := t.TempDir()
	t.Chdir(projectDir)

	if err := os.MkdirAll(filepath.Join(tempHome, ".bomly"), 0o755); err != nil {
		t.Fatalf("mkdir home config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(tempHome, ".bomly", "config.yaml"), map[string]any{
		"components": map[string]any{
			"detectors": "syft-detector",
		},
		"policy": map[string]any{
			"fail_on": "low",
		},
		"output": map[string]any{
			"format": "text",
		},
		"matchers": map[string]any{
			"osv": map[string]any{
				"cache_ttl": "1h",
			},
		},
	})

	if err := os.MkdirAll(filepath.Join(projectDir, ".bomly"), 0o755); err != nil {
		t.Fatalf("mkdir project config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(projectDir, ".bomly", "config.yaml"), map[string]any{
		"components": map[string]any{
			"detectors": "go-detector",
			"matchers":  "osv",
		},
		"policy": map[string]any{
			"fail_on": "medium",
		},
		"output": map[string]any{
			"format": "json",
		},
		"matchers": map[string]any{
			"osv": map[string]any{
				"cache_ttl": "2h",
			},
		},
	})

	explicitConfig := filepath.Join(t.TempDir(), "bomly.yaml")
	writeConfigFile(t, explicitConfig, map[string]any{
		"components": map[string]any{
			"auditors": "policy-auditor",
		},
		"policy": map[string]any{
			"fail_on": "high",
		},
		"matchers": map[string]any{
			"osv": map[string]any{
				"cache_ttl": "4h",
			},
		},
	})

	options := &Options{}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupAnalysis, FlagGroupSelectors); err != nil {
		t.Fatalf("BindCommandFlagGroups() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--config", explicitConfig, "--fail-on", "low", "--ecosystems", "python"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}

	got := options.GetConfig()
	if len(got.FailOn) != 1 || got.FailOn[0] != "low" {
		t.Fatalf("expected flag fail_on override [low], got %v", got.FailOn)
	}
	if got.Ecosystems != "python" {
		t.Fatalf("expected flag ecosystems override, got %q", got.Ecosystems)
	}
	if got.Format != "sarif" {
		t.Fatalf("expected env format override, got %q", got.Format)
	}
	if got.OsvCacheTTL != "3h" {
		t.Fatalf("expected env OSV cache TTL override, got %q", got.OsvCacheTTL)
	}
	if got.Auditors != "policy-auditor" {
		t.Fatalf("expected explicit config auditors override, got %q", got.Auditors)
	}
	if got.Matchers != "" {
		t.Fatalf("repository config unexpectedly selected matchers %q", got.Matchers)
	}
	if got.Detectors != "syft-detector" {
		t.Fatalf("expected user config detector, got %q", got.Detectors)
	}
	if got.OsvAPIBase != "https://api.osv.dev" {
		t.Fatalf("expected default OSV API base, got %q", got.OsvAPIBase)
	}
	if len(got.LoadedFiles) != 2 {
		t.Fatalf("expected user and explicit config files, got %#v", got.LoadedFiles)
	}
}

func TestCommandContextInitialize_JSONShortcutOverridesEnvFormat(t *testing.T) {
	t.Setenv("BOMLY_FORMAT", "markdown")

	options := &Options{}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupExecution); err != nil {
		t.Fatalf("BindCommandFlagGroups() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--json"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if got := options.GetConfig().Format; got != "json" {
		t.Fatalf("expected --json to override env format, got %q", got)
	}
}

func TestCommandContextInitialize_JSONFalseDoesNotOverrideEnvFormat(t *testing.T) {
	t.Setenv("BOMLY_FORMAT", "markdown")

	options := &Options{}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupExecution); err != nil {
		t.Fatalf("BindCommandFlagGroups() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--json=false"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if got := options.GetConfig().Format; got != "markdown" {
		t.Fatalf("expected --json=false to preserve env format, got %q", got)
	}
}

func TestCommandContextInitialize_LoadsQuietFromConfig(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	projectDir := t.TempDir()
	t.Chdir(projectDir)

	if err := os.MkdirAll(filepath.Join(tempHome, ".bomly"), 0o755); err != nil {
		t.Fatalf("mkdir home config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(tempHome, ".bomly", "config.yaml"), map[string]any{
		"logging": map[string]any{
			"quiet": true,
		},
	})

	options := &Options{}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("initialize() error = %v", err)
	}

	if !options.GetConfig().Quiet {
		t.Fatal("expected quiet value from config")
	}
}

func TestCommandContextInitialize_RejectsQuietAndVerboseTogether(t *testing.T) {
	options := &Options{ResolvedConfig: config.Resolved{Quiet: true, Verbosity: 1}}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--quiet", "--verbose"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	err := options.ResolveConfig(root)
	if err == nil {
		t.Fatal("expected quiet and verbose validation error")
	}
	if !strings.Contains(err.Error(), "--quiet cannot be combined with --verbose") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCommandContextInitialize_RequiresExplicitProjectConfig(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".bomly"), 0o755); err != nil {
		t.Fatalf("mkdir project config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(projectDir, ".bomly", "config.yaml"), map[string]any{
		"components": map[string]any{
			"ecosystems": "go",
		},
	})

	configPath := filepath.Join(projectDir, ".bomly", "config.yaml")
	tests := []struct {
		name       string
		args       []string
		wantConfig bool
	}{
		{
			name: "path does not authorize repository config",
			args: []string{"--path", projectDir},
		},
		{
			name:       "config flag authorizes repository config",
			args:       []string{"--path", projectDir, "--config", configPath},
			wantConfig: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &Options{ResolvedConfig: config.Resolved{Path: projectDir}}
			root := newTestRootCommand(t)
			if err := options.Bind(root); err != nil {
				t.Fatalf("Bind() error = %v", err)
			}
			if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupTarget); err != nil {
				t.Fatalf("BindCommandFlagGroups() error = %v", err)
			}
			if err := root.ParseFlags(tt.args); err != nil {
				t.Fatalf("ParseFlags() error = %v", err)
			}
			if err := options.ResolveConfig(root); err != nil {
				t.Fatalf("ResolveConfig() error = %v", err)
			}

			got := options.GetConfig()
			if tt.wantConfig {
				if got.Ecosystems != "go" {
					t.Fatalf("explicit project config ecosystems = %q, want go", got.Ecosystems)
				}
				if len(got.LoadedFiles) != 1 || got.LoadedFiles[0] != configPath {
					t.Fatalf("loaded files = %#v, want explicit project config", got.LoadedFiles)
				}
				return
			}
			if got.Ecosystems != "" {
				t.Fatalf("implicitly loaded project config ecosystems %q", got.Ecosystems)
			}
			if len(got.LoadedFiles) != 0 {
				t.Fatalf("implicitly loaded config files %#v", got.LoadedFiles)
			}
		})
	}
}

func TestCommandContextInitialize_RepositoryConfigCannotGrantAuthorityImplicitly(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	projectDir := t.TempDir()
	configDir := filepath.Join(projectDir, ".bomly")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir project config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(configDir, "config.yaml"), map[string]any{
		"target": map[string]any{
			"url": "https://attacker.example/repository.git",
		},
		"pipeline": map[string]any{
			"enrich":        true,
			"install_first": true,
			"install_args":  []string{"--unsafe"},
		},
		"components": map[string]any{
			"detectors": "+attacker.detector",
			"matchers":  "+attacker.matcher",
		},
		"output": map[string]any{
			"outputs": []string{"json=/tmp/attacker-output.json"},
		},
		"network": map[string]any{
			"proxy": map[string]any{
				"url": "http://attacker.example:8080",
			},
			"ca_cert_file": "attacker-ca.pem",
		},
		"matchers": map[string]any{
			"osv": map[string]any{
				"api_base":  "http://127.0.0.1:8080",
				"cache_dir": "/tmp/attacker-cache",
			},
		},
		"plugins": map[string]any{
			"attacker.matcher": map[string]any{
				"endpoint": "http://127.0.0.1:9090",
			},
		},
	})

	options := &Options{ResolvedConfig: config.Resolved{Path: projectDir}}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupTarget); err != nil {
		t.Fatalf("BindCommandFlagGroups() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--path", projectDir}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}

	got := options.GetConfig()
	if got.URL != "" || got.Enrich || got.InstallFirst ||
		len(got.InstallArgs) != 0 || got.Detectors != "" || got.Matchers != "" ||
		len(got.Outputs) != 0 || got.HTTPProxy != "" ||
		got.OsvAPIBase != "https://api.osv.dev" || got.OsvCacheDir != "" ||
		len(got.Plugins) != 0 || len(got.LoadedFiles) != 0 {
		t.Fatalf("repository config granted authority without --config: %#v", got)
	}
}

func TestCommandContextInitialize_ExplicitConfigResolvesRelativeCAPathAndPrivateNetworkSettings(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "trusted.yaml")
	writeConfigFile(t, configPath, map[string]any{
		"network": map[string]any{
			"proxy": map[string]any{
				"url":      "http://proxy.internal.test:8080",
				"no_proxy": "advisories.internal.test,127.0.0.0/8",
			},
			"ca_cert_file": "private-ca.pem",
		},
		"matchers": map[string]any{
			"osv": map[string]any{
				"api_base": "http://127.0.0.1:8081",
			},
			"scorecard": map[string]any{
				"api_base": "https://scorecard.internal.test",
			},
		},
		"plugins": map[string]any{
			"private.matcher": map[string]any{
				"endpoint": "https://advisories.internal.test",
			},
		},
	})

	options := &Options{}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--config", configPath}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}

	got := options.GetConfig()
	if got.HTTPProxy != "http://proxy.internal.test:8080" {
		t.Fatalf("HTTP proxy = %q", got.HTTPProxy)
	}
	if got.HTTPNoProxy != "advisories.internal.test,127.0.0.0/8" {
		t.Fatalf("HTTP no-proxy = %q", got.HTTPNoProxy)
	}
	// CA paths are resolved from the selected config file, not the process CWD.
	if got.HTTPCACertFile != filepath.Join(configDir, "private-ca.pem") {
		t.Fatalf("HTTP CA certificate = %q", got.HTTPCACertFile)
	}
	if got.OsvAPIBase != "http://127.0.0.1:8081" {
		t.Fatalf("OSV API base = %q", got.OsvAPIBase)
	}
	if got.ScorecardAPIBase != "https://scorecard.internal.test" {
		t.Fatalf("Scorecard API base = %q", got.ScorecardAPIBase)
	}
	if got.Plugins["private.matcher"]["endpoint"] != "https://advisories.internal.test" {
		t.Fatalf("plugin config = %#v", got.Plugins)
	}
	if len(got.LoadedFiles) != 1 || got.LoadedFiles[0] != configPath {
		t.Fatalf("loaded files = %#v, want explicit config", got.LoadedFiles)
	}
}

func TestCommandContextInitialize_ConfigSelection(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	envConfig := filepath.Join(t.TempDir(), "env.yaml")
	writeConfigFile(t, envConfig, map[string]any{
		"components": map[string]any{"ecosystems": "npm"},
	})
	flagConfig := filepath.Join(t.TempDir(), "flag.yaml")
	writeConfigFile(t, flagConfig, map[string]any{
		"components": map[string]any{"ecosystems": "go"},
	})
	t.Setenv("BOMLY_CONFIG", envConfig)

	tests := []struct {
		name       string
		args       []string
		wantConfig string
		wantValue  string
	}{
		{
			name:       "environment selects config",
			wantConfig: envConfig,
			wantValue:  "npm",
		},
		{
			name:       "flag overrides environment selection",
			args:       []string{"--config", flagConfig},
			wantConfig: flagConfig,
			wantValue:  "go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &Options{}
			root := newTestRootCommand(t)
			if err := options.Bind(root); err != nil {
				t.Fatalf("Bind() error = %v", err)
			}
			if err := root.ParseFlags(tt.args); err != nil {
				t.Fatalf("ParseFlags() error = %v", err)
			}
			if err := options.ResolveConfig(root); err != nil {
				t.Fatalf("ResolveConfig() error = %v", err)
			}
			got := options.GetConfig()
			if got.Config != tt.wantConfig || got.Ecosystems != tt.wantValue {
				t.Fatalf("config/value = %q/%q, want %q/%q", got.Config, got.Ecosystems, tt.wantConfig, tt.wantValue)
			}
			if len(got.LoadedFiles) != 1 || got.LoadedFiles[0] != tt.wantConfig {
				t.Fatalf("loaded files = %#v, want %q", got.LoadedFiles, tt.wantConfig)
			}
		})
	}
}

func TestCommandContextInitialize_RejectsInvalidExplicitConfig(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	tests := []struct {
		name      string
		path      string
		wantError string
	}{
		{
			name:      "missing file",
			path:      filepath.Join(t.TempDir(), "missing.yaml"),
			wantError: "resolve config path",
		},
		{
			name:      "directory",
			path:      t.TempDir(),
			wantError: "must be a regular file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &Options{}
			root := newTestRootCommand(t)
			if err := options.Bind(root); err != nil {
				t.Fatalf("Bind() error = %v", err)
			}
			if err := root.ParseFlags([]string{"--config", tt.path}); err != nil {
				t.Fatalf("ParseFlags() error = %v", err)
			}
			err := options.ResolveConfig(root)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("ResolveConfig() error = %v, want %q", err, tt.wantError)
			}
		})
	}
}

func writeConfigFile(t *testing.T, path string, value map[string]any) {
	t.Helper()
	data, err := yaml.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func newTestRootCommand(t *testing.T) *cobra.Command {
	t.Helper()
	return &cobra.Command{Use: "bomly"}
}

func containsOption(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsManager(values []sdk.PackageManager, target sdk.PackageManager) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestResolveConfigRejectsMaxDepthWithoutRecursive(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)
	t.Chdir(t.TempDir())

	options := &Options{}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupTarget); err != nil {
		t.Fatalf("BindCommandFlagGroups() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--max-depth", "2"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	err := options.ResolveConfig(root)
	if err == nil {
		t.Fatal("expected error for explicit --max-depth without --recursive")
	}
	if !strings.Contains(err.Error(), "--max-depth requires --recursive") {
		t.Fatalf("expected --max-depth gating message, got %q", err.Error())
	}
}

func TestResolveConfigAcceptsMaxDepthWithRecursive(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)
	t.Chdir(t.TempDir())

	options := &Options{}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupTarget); err != nil {
		t.Fatalf("BindCommandFlagGroups() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--recursive", "--max-depth", "2", "--exclude", "apps/*,dist"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	got := options.GetConfig()
	if !got.Recursive || got.MaxDepth != 2 {
		t.Fatalf("expected recursive with max depth 2, got %+v", got)
	}
	if len(got.ExcludePaths) != 2 || got.ExcludePaths[0] != "apps/*" || got.ExcludePaths[1] != "dist" {
		t.Fatalf("expected CSV exclude parsing, got %#v", got.ExcludePaths)
	}
}

func TestResolveConfigDefaultsMaxDepthWithoutFlags(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)
	t.Chdir(t.TempDir())

	options := &Options{}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := BindCommandFlagGroups(root, &options.ResolvedConfig, FlagGroupTarget); err != nil {
		t.Fatalf("BindCommandFlagGroups() error = %v", err)
	}
	if err := root.ParseFlags(nil); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	got := options.GetConfig()
	if got.Recursive {
		t.Fatal("expected recursive discovery to default off")
	}
	if got.MaxDepth != 3 {
		t.Fatalf("expected default max depth 3, got %d", got.MaxDepth)
	}
}
