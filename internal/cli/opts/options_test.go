package opts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/registry"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
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

func TestCommandContextResolveExecutionTarget_Container(t *testing.T) {
	options := Options{ResolvedConfig: config.Resolved{Container: "alpine:3.20"}}

	target, location, cleanup, err := options.resolveExecutionTarget(nil)
	if err != nil {
		t.Fatalf("resolveExecutionTarget() error = %v", err)
	}
	if cleanup != nil {
		t.Fatal("expected no cleanup for container target")
	}
	if target.Kind != model.ExecutionTargetContainerImage {
		t.Fatalf("expected container execution target, got %#v", target)
	}
	if target.Location != "alpine:3.20" || location != "alpine:3.20" {
		t.Fatalf("unexpected container target values: %#v %q", target, location)
	}
}

func TestCommandContextResolveExecutionTarget_RejectsMultipleTargets(t *testing.T) {
	options := Options{ResolvedConfig: config.Resolved{Path: ".", Container: "alpine:3.20"}}

	_, _, _, err := options.resolveExecutionTarget(nil)
	if err == nil {
		t.Fatal("expected multiple target error")
	}
	if !strings.Contains(err.Error(), "--path, --url, and --container cannot be used together") {
		t.Fatalf("unexpected error: %v", err)
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

	for _, want := range []model.PackageManager{
		model.PackageManagerPip,
		model.PackageManagerPipenv,
		model.PackageManagerPoetry,
		model.PackageManagerUV,
	} {
		if !containsManager(managers, want) {
			t.Fatalf("expected package manager %q in %#v", want, managers)
		}
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

	for _, want := range []model.PackageManager{
		model.PackageManagerCargo,
		model.PackageManagerTerraform,
		model.PackageManagerComposer,
		model.PackageManagerPDM,
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

	for _, flagName := range []string{"ecosystems", "detectors", "auditors", "matchers"} {
		flag := root.PersistentFlags().Lookup(flagName)
		if flag == nil {
			t.Fatalf("expected flag %q to exist", flagName)
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

func TestCommandContextInitialize_LoadsConfigHierarchy(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	projectDir := t.TempDir()
	t.Chdir(projectDir)

	if err := os.MkdirAll(filepath.Join(tempHome, ".bomly"), 0o755); err != nil {
		t.Fatalf("mkdir home config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(tempHome, ".bomly", "config.yaml"), map[string]any{
		"ecosystems": "npm",
		"detectors":  "syft-detector",
		"verbose":    true,
	})

	if err := os.MkdirAll(filepath.Join(projectDir, ".bomly"), 0o755); err != nil {
		t.Fatalf("mkdir project config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(projectDir, ".bomly", "config.yaml"), map[string]any{
		"ecosystems": "go",
		"detectors":  "go-detector",
	})

	explicitConfig := filepath.Join(t.TempDir(), "bomly.yaml")
	writeConfigFile(t, explicitConfig, map[string]any{
		"detectors": "maven-detector",
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
	if len(got.LoadedFiles) != 3 {
		t.Fatalf("expected 3 loaded config files, got %#v", got.LoadedFiles)
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
		"detectors":     "syft-detector",
		"fail_on":       "low",
		"format":        "text",
		"osv_cache_ttl": "1h",
	})

	if err := os.MkdirAll(filepath.Join(projectDir, ".bomly"), 0o755); err != nil {
		t.Fatalf("mkdir project config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(projectDir, ".bomly", "config.yaml"), map[string]any{
		"detectors":     "go-detector",
		"fail_on":       "medium",
		"format":        "json",
		"matchers":      "osv",
		"osv_cache_ttl": "2h",
	})

	explicitConfig := filepath.Join(t.TempDir(), "bomly.yaml")
	writeConfigFile(t, explicitConfig, map[string]any{
		"auditors":      "policy-auditor",
		"fail_on":       "high",
		"osv_cache_ttl": "4h",
	})

	options := &Options{}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--config", explicitConfig, "--fail-on", "low", "--ecosystems", "python"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}

	got := options.GetConfig()
	if got.FailOn != "low" {
		t.Fatalf("expected flag fail_on override, got %q", got.FailOn)
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
	if got.Matchers != "osv" {
		t.Fatalf("expected project config matchers override, got %q", got.Matchers)
	}
	if got.Detectors != "go-detector" {
		t.Fatalf("expected project config detectors override home config, got %q", got.Detectors)
	}
	if got.OsvAPIBase != "https://api.osv.dev" {
		t.Fatalf("expected default OSV API base, got %q", got.OsvAPIBase)
	}
	if len(got.LoadedFiles) != 3 {
		t.Fatalf("expected 3 loaded config files, got %#v", got.LoadedFiles)
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
		"quiet": true,
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

func TestCommandContextInitialize_ProjectConfigUsesSelectedPath(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".bomly"), 0o755); err != nil {
		t.Fatalf("mkdir project config dir: %v", err)
	}
	writeConfigFile(t, filepath.Join(projectDir, ".bomly", "config.yaml"), map[string]any{
		"ecosystems": "go",
	})

	options := &Options{ResolvedConfig: config.Resolved{Path: projectDir}}
	root := newTestRootCommand(t)
	if err := options.Bind(root); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--path", projectDir}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.ResolveConfig(root); err != nil {
		t.Fatalf("initialize() error = %v", err)
	}

	if got := options.GetConfig().Ecosystems; got != "go" {
		t.Fatalf("expected project config ecosystems, got %q", got)
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

func containsManager(values []model.PackageManager, target model.PackageManager) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
