package cli

import (
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

func TestDiscoverSubprojects_FindsRootPackageManagers(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.com/api\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	subprojects, err := discoverSubprojects(model.ExecutionTarget{Kind: model.ExecutionTargetWorkingDirectory, Location: projectDir})
	if err != nil {
		t.Fatalf("discoverSubprojects() error = %v", err)
	}
	if len(subprojects) != 2 {
		t.Fatalf("expected 2 subprojects, got %d", len(subprojects))
	}
	if subprojects[0].RelativePath != "." || subprojects[0].PrimaryPackageManager() != model.PackageManagerGoMod {
		t.Fatalf("unexpected first subproject: %#v", subprojects[0])
	}
	if subprojects[1].RelativePath != "." || subprojects[1].PrimaryPackageManager() != model.PackageManagerNPM {
		t.Fatalf("unexpected second subproject: %#v", subprojects[1])
	}
}

func TestGlobalOptionsResolveSubprojects_AppliesEcosystemFilter(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.com/demo\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	options := globalOptions{Resolved: config.Resolved{Ecosystems: "go,npm"}}
	subprojects, err := options.resolveSubprojects(model.ExecutionTarget{Kind: model.ExecutionTargetWorkingDirectory, Location: projectDir})
	if err != nil {
		t.Fatalf("resolveSubprojects() error = %v", err)
	}
	if len(subprojects) != 2 {
		t.Fatalf("expected 2 filtered subprojects, got %d", len(subprojects))
	}

	options = globalOptions{Resolved: config.Resolved{Ecosystems: "go"}}
	subprojects, err = options.resolveSubprojects(model.ExecutionTarget{Kind: model.ExecutionTargetWorkingDirectory, Location: projectDir})
	if err != nil {
		t.Fatalf("resolveSubprojects() error = %v", err)
	}
	if len(subprojects) != 1 {
		t.Fatalf("expected 1 filtered subproject, got %d", len(subprojects))
	}
	if subprojects[0].Ecosystem != model.EcosystemGo {
		t.Fatalf("expected go subproject, got %#v", subprojects[0])
	}
}

func TestGlobalOptionsResolveExecutionTarget_Container(t *testing.T) {
	options := globalOptions{Resolved: config.Resolved{Container: "alpine:3.20"}}

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

func TestGlobalOptionsResolveExecutionTarget_RejectsMultipleTargets(t *testing.T) {
	options := globalOptions{Resolved: config.Resolved{Path: ".", Container: "alpine:3.20"}}

	_, _, _, err := options.resolveExecutionTarget(nil)
	if err == nil {
		t.Fatal("expected multiple target error")
	}
	if !strings.Contains(err.Error(), "--path, --url, and --container cannot be used together") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGlobalOptionsResolveSubprojects_SingleFileUsesRegistryIndexedManager(t *testing.T) {
	projectFile := filepath.Join(t.TempDir(), "Cargo.lock")
	if err := os.WriteFile(projectFile, []byte("version = 3\n"), 0o644); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}

	options := globalOptions{Resolved: config.Resolved{Path: projectFile}}
	subprojects, err := options.resolveSubprojects(model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: projectFile})
	if err != nil {
		t.Fatalf("resolveSubprojects() error = %v", err)
	}
	if len(subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(subprojects))
	}
	if subprojects[0].PrimaryPackageManager() != model.PackageManagerCargo || subprojects[0].Ecosystem != model.EcosystemRust {
		t.Fatalf("unexpected single-file subproject: %#v", subprojects[0])
	}
}

func TestGlobalOptionsResolveSubprojects_ContainerUsesGenericDiscoveryTarget(t *testing.T) {
	options := globalOptions{}
	subprojects, err := options.resolveSubprojects(model.ExecutionTarget{Kind: model.ExecutionTargetContainerImage, Location: "alpine:3.20"})
	if err != nil {
		t.Fatalf("resolveSubprojects() error = %v", err)
	}
	if len(subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(subprojects))
	}
	if subprojects[0].PrimaryPackageManager() != model.PackageManagerUnknown || subprojects[0].Ecosystem != model.EcosystemUnknown {
		t.Fatalf("unexpected container subproject: %#v", subprojects[0])
	}
	if len(subprojects[0].PlannedDetectors) != 1 || subprojects[0].PlannedDetectors[0] != "syft-detector" {
		t.Fatalf("expected syft detector chain, got %#v", subprojects[0].PlannedDetectors)
	}
}

func TestGlobalOptionsResolveSubprojects_ContainerAppliesEcosystemFilter(t *testing.T) {
	options := globalOptions{Resolved: config.Resolved{Ecosystems: "rpm"}}
	subprojects, err := options.resolveSubprojects(model.ExecutionTarget{Kind: model.ExecutionTargetContainerImage, Location: "alpine:3.20"})
	if err != nil {
		t.Fatalf("resolveSubprojects() error = %v", err)
	}
	if len(subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(subprojects))
	}
	if subprojects[0].Ecosystem != model.EcosystemRPM {
		t.Fatalf("expected rpm ecosystem, got %#v", subprojects[0])
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

	containerOS := availableContainerOSOptions()
	for _, want := range []string{"alpine", "ubuntu", "wolfi", "rhel", "amzn"} {
		if !containsOption(containerOS, want) {
			t.Fatalf("expected container os option %q in %#v", want, containerOS)
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

func TestGlobalOptionsBind_AnnotatesUsageWithAvailableOptions(t *testing.T) {
	options := &globalOptions{}
	root := newTestRootCommand(t)

	if err := options.bind(root); err != nil {
		t.Fatalf("bind() error = %v", err)
	}

	for _, flagName := range []string{"ecosystems", "detectors", "auditors", "matchers"} {
		flag := root.PersistentFlags().Lookup(flagName)
		if flag == nil {
			t.Fatalf("expected flag %q to exist", flagName)
		}
	}
}

func TestRootHelp_IncludesAvailableOptionValuesSection(t *testing.T) {
	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	helpText := output.String()
	if !strings.Contains(helpText, "Explore available detectors, matchers, and auditors with `bomly plugin list`.") {
		t.Fatalf("expected help output to contain plugin list guidance, got:\n%s", helpText)
	}

	for _, removed := range []string{
		"Available Native Detectors:",
		"Available Third-party Detectors:",
		"Available Auditors:",
		"Available Matchers:",
	} {
		if strings.Contains(helpText, removed) {
			t.Fatalf("expected help output to omit %q, got:\n%s", removed, helpText)
		}
	}
}

func TestRootVersion_IncludesTrackedDependencyVersions(t *testing.T) {
	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	versionText := output.String()
	if !strings.Contains(versionText, "bomly 0.9.0-test") {
		t.Fatalf("expected version output to contain core version, got:\n%s", versionText)
	}
	for _, item := range selectedDependencyVersions() {
		want := item.Label + ":"
		if !strings.Contains(versionText, want) {
			t.Fatalf("expected version output to contain %q, got:\n%s", want, versionText)
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

func TestGlobalOptionsInitialize_LoadsConfigHierarchy(t *testing.T) {
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

	options := &globalOptions{
		Resolved: config.Resolved{
			Config:     explicitConfig,
			Ecosystems: "python",
		},
	}
	root := newTestRootCommand(t)
	if err := options.bind(root); err != nil {
		t.Fatalf("bind() error = %v", err)
	}
	root.SetArgs([]string{"--config", explicitConfig, "--ecosystems", "python"})
	if err := root.ParseFlags(root.Flags().Args()); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--config", explicitConfig, "--ecosystems", "python"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.initialize(root); err != nil {
		t.Fatalf("initialize() error = %v", err)
	}

	got := options.current()
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

func TestGlobalOptionsInitialize_LoadsQuietFromConfig(t *testing.T) {
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

	options := &globalOptions{}
	root := newTestRootCommand(t)
	if err := options.bind(root); err != nil {
		t.Fatalf("bind() error = %v", err)
	}
	if err := options.initialize(root); err != nil {
		t.Fatalf("initialize() error = %v", err)
	}

	if !options.current().Quiet {
		t.Fatal("expected quiet value from config")
	}
}

func TestGlobalOptionsInitialize_RejectsQuietAndVerboseTogether(t *testing.T) {
	options := &globalOptions{Resolved: config.Resolved{Quiet: true, Verbosity: 1}}
	root := newTestRootCommand(t)
	if err := options.bind(root); err != nil {
		t.Fatalf("bind() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--quiet", "--verbose"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	err := options.initialize(root)
	if err == nil {
		t.Fatal("expected quiet and verbose validation error")
	}
	if !strings.Contains(err.Error(), "--quiet cannot be combined with --verbose") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGlobalOptionsInitialize_ProjectConfigUsesSelectedPath(t *testing.T) {
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

	options := &globalOptions{Resolved: config.Resolved{Path: projectDir}}
	root := newTestRootCommand(t)
	if err := options.bind(root); err != nil {
		t.Fatalf("bind() error = %v", err)
	}
	if err := root.ParseFlags([]string{"--path", projectDir}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	if err := options.initialize(root); err != nil {
		t.Fatalf("initialize() error = %v", err)
	}

	if got := options.current().Ecosystems; got != "go" {
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
