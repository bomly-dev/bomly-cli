package plugin_test

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/internal/testutil"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func TestInstallDevBinaryVerifyEnableDisableAndUninstall(t *testing.T) {
	root := t.TempDir()
	binaryPath := filepath.Join(t.TempDir(), executableName("bomly-plugin-fake"))
	if err := testutil.BuildGoBinary(t, binaryPath, fakeDetectorPluginSource("acme.detector.fake")); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}

	result, err := managedplugin.Install(context.Background(), root, binaryPath, managedplugin.InstallOptions{DevBinary: true})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if result.Manifest.ID != "acme.detector.fake" {
		t.Fatalf("expected installed id acme.detector.fake, got %q", result.Manifest.ID)
	}
	if result.Installed.Enabled {
		t.Fatalf("expected plugin install to record disabled state by default")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(result.Installed.Path, "bomly-plugin.json"))
	if err != nil {
		t.Fatalf("read installed manifest: %v", err)
	}
	manifestJSON := string(manifestBytes)
	if strings.Contains(manifestJSON, "supportedEcosystems") || strings.Contains(manifestJSON, "supportedManagers") {
		t.Fatalf("expected installed manifest to derive ecosystem and manager support from packageManagerSupport, got %s", manifestJSON)
	}

	verifyResult, err := managedplugin.Verify(context.Background(), root, "acme.detector.fake")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(verifyResult.Checks) == 0 {
		t.Fatalf("expected verify checks, got none")
	}

	if _, err := managedplugin.Disable(root, "acme.detector.fake"); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	installed, err := managedplugin.LoadInstalledPlugins(root)
	if err != nil {
		t.Fatalf("LoadInstalledPlugins() error = %v", err)
	}
	if len(installed) != 1 || installed[0].Enabled {
		t.Fatalf("expected plugin to be disabled")
	}
	if got := installed[0].DetectorDescriptor.SupportedManagers; len(got) != 1 || got[0] != sdk.PackageManagerGoMod {
		t.Fatalf("expected loaded manifest to derive supported manager gomod, got %#v", got)
	}

	if _, err := managedplugin.Enable(root, "acme.detector.fake"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}
	installed, err = managedplugin.LoadInstalledPlugins(root)
	if err != nil {
		t.Fatalf("LoadInstalledPlugins() error = %v", err)
	}
	if len(installed) != 1 || !installed[0].Enabled {
		t.Fatalf("expected plugin to be enabled")
	}

	if err := managedplugin.Uninstall(root, "acme.detector.fake"); err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	installed, err = managedplugin.LoadInstalledPlugins(root)
	if err != nil {
		t.Fatalf("LoadInstalledPlugins() error = %v", err)
	}
	if len(installed) != 0 {
		t.Fatalf("expected plugin to be removed from installed database")
	}
}

func TestEnableDisableUseDefaultPluginRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv(managedplugin.EnvPluginHome, root)

	binaryPath := filepath.Join(t.TempDir(), executableName("bomly-plugin-fake"))
	if err := testutil.BuildGoBinary(t, binaryPath, fakeDetectorPluginSource("acme.detector.default-root")); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}

	if _, err := managedplugin.Install(context.Background(), "", binaryPath, managedplugin.InstallOptions{DevBinary: true}); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if _, err := managedplugin.Enable("", "acme.detector.default-root"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}

	installed, err := managedplugin.LoadInstalledPlugins("")
	if err != nil {
		t.Fatalf("LoadInstalledPlugins() error = %v", err)
	}
	if len(installed) != 1 || !installed[0].Enabled {
		t.Fatalf("expected plugin to be enabled via default root lookup")
	}

	if _, err := managedplugin.Disable("", "acme.detector.default-root"); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	installed, err = managedplugin.LoadInstalledPlugins("")
	if err != nil {
		t.Fatalf("LoadInstalledPlugins() error = %v", err)
	}
	if len(installed) != 1 || installed[0].Enabled {
		t.Fatalf("expected plugin to be disabled via default root lookup")
	}
}

func TestInstallDevBinaryResolvesWindowsExeSuffix(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-specific executable suffix behavior")
	}

	root := t.TempDir()
	binaryWithoutExt := filepath.Join(t.TempDir(), "bomly-plugin-fake")
	if err := testutil.BuildGoBinary(t, binaryWithoutExt, fakeDetectorPluginSource("acme.detector.fake")); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}
	if _, err := os.Stat(binaryWithoutExt); err != nil {
		t.Fatalf("expected extensionless plugin binary to exist: %v", err)
	}

	result, err := managedplugin.Install(context.Background(), root, binaryWithoutExt, managedplugin.InstallOptions{DevBinary: true})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if result.Manifest.ID != "acme.detector.fake" {
		t.Fatalf("expected installed id acme.detector.fake, got %q", result.Manifest.ID)
	}
}

func TestInstallRejectsUnsafeArchivePaths(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(t.TempDir(), "unsafe.zip")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	zipWriter := zip.NewWriter(file)
	writer, err := zipWriter.Create("../escape.txt")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := writer.Write([]byte("boom")); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive file: %v", err)
	}

	_, err = managedplugin.Install(context.Background(), root, archivePath, managedplugin.InstallOptions{})
	if err == nil || !strings.Contains(err.Error(), "escapes the extraction directory") {
		t.Fatalf("expected unsafe archive path error, got %v", err)
	}
}

func TestInstallDevBinaryRejectsDetectorWithoutPackageManagers(t *testing.T) {
	root := t.TempDir()
	binaryPath := filepath.Join(t.TempDir(), executableName("bomly-plugin-fake"))
	if err := testutil.BuildGoBinary(t, binaryPath, fakeDetectorPluginSourceWithoutPackageManagers("acme.detector.invalid")); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}

	_, err := managedplugin.Install(context.Background(), root, binaryPath, managedplugin.InstallOptions{DevBinary: true})
	if err == nil || !strings.Contains(err.Error(), "detector plugins must declare at least one package manager") {
		t.Fatalf("expected missing package managers error, got %v", err)
	}
}

func TestPrepareLoadsAndRunsExternalDetector(t *testing.T) {
	root := t.TempDir()
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.com/demo\n\ngo 1.25.0\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	binaryPath := filepath.Join(t.TempDir(), executableName("bomly-plugin-gomod"))
	if err := testutil.BuildGoBinary(t, binaryPath, fakeDetectorPluginSource("acme.detector.gomod")); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}
	if _, err := managedplugin.Install(context.Background(), root, binaryPath, managedplugin.InstallOptions{DevBinary: true}); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if _, err := managedplugin.Enable(root, "acme.detector.gomod"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}

	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	if err := managedplugin.RegisterRuntimePlugins(context.Background(), reg, root); err != nil {
		t.Fatalf("RegisterRuntimePlugins() error = %v", err)
	}
	filtered := reg.Filter(engine.RegistryFilter{
		DetectorFilter:  sdk.DetectorFilter{Include: []string{"acme.detector.gomod"}},
		EcosystemFilter: sdk.EcosystemFilter{Include: []sdk.Ecosystem{sdk.EcosystemGo}},
	})
	subprojects, err := opts.PlanSubprojects(filtered, opts.Request{
		Registry:        reg,
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectDir},
		DetectorFilter:  sdk.DetectorFilter{Include: []string{"acme.detector.gomod"}},
		EcosystemFilter: sdk.EcosystemFilter{Include: []sdk.Ecosystem{sdk.EcosystemGo}},
	})
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	if len(subprojects) != 1 {
		t.Fatalf("expected one external plugin subproject, got %d", len(subprojects))
	}
	if subprojects[0].PrimaryDetector != "acme.detector.gomod" {
		t.Fatalf("expected external detector to be planned, got %q", subprojects[0].PrimaryDetector)
	}

	detectors := filtered.PlannedDetectors(sdk.DetectionRequest{
		ProjectPath:     projectDir,
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectDir},
		Subproject:      subprojects[0],
		Ecosystem:       sdk.EcosystemGo,
		PackageManager:  sdk.PackageManagerGoMod,
	}, []string{"acme.detector.gomod"})
	if len(detectors) != 1 {
		t.Fatalf("expected one planned detector, got %d", len(detectors))
	}
	result, err := detectors[0].ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     projectDir,
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectDir},
		Subproject:      subprojects[0],
		Ecosystem:       sdk.EcosystemGo,
		PackageManager:  sdk.PackageManagerGoMod,
		ScopeFilter:     sdk.ScopeRuntime,
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	graph, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if graph == nil || graph.Size() != 1 {
		t.Fatalf("expected one package in plugin graph, got %#v", graph)
	}
	if _, ok := graph.Node("example.com/runtime@v1.0.0"); !ok {
		t.Fatalf("expected plugin detector to receive runtime scope, got %s", graph.PrettyString())
	}
}

func TestExternalMatcherReceivesAndReturnsRegistry(t *testing.T) {
	root := t.TempDir()
	binaryPath := filepath.Join(t.TempDir(), executableName("bomly-plugin-matcher"))
	if err := testutil.BuildGoBinary(t, binaryPath, fakeMatcherPluginSource("acme.matcher.registry")); err != nil {
		t.Fatalf("build fake matcher plugin: %v", err)
	}
	if _, err := managedplugin.Install(context.Background(), root, binaryPath, managedplugin.InstallOptions{DevBinary: true}); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if _, err := managedplugin.Enable(root, "acme.matcher.registry"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}

	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	if err := managedplugin.RegisterRuntimePlugins(context.Background(), reg, root); err != nil {
		t.Fatalf("RegisterRuntimePlugins() error = %v", err)
	}
	matchers := reg.Matchers(sdk.MatchRequest{
		MatcherFilter: sdk.MatcherFilter{Include: []string{"acme.matcher.registry"}},
	})
	if len(matchers) != 1 {
		t.Fatalf("expected one external matcher, got %d", len(matchers))
	}

	const purl = "pkg:npm/react@18.2.0"
	registry := sdk.NewPackageRegistry()
	registry.Ensure(purl).Name = "react"
	result, err := matchers[0].Match(context.Background(), sdk.MatchRequest{
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if result.Registry == nil {
		t.Fatal("expected external matcher to return registry")
	}
	pkg, ok := result.Registry.Get(purl)
	if !ok {
		t.Fatalf("expected matched package %q", purl)
	}
	if len(pkg.Licenses) != 1 || pkg.Licenses[0].SPDXExpression != "MIT" {
		t.Fatalf("expected registry enrichment from external matcher, got %#v", pkg.Licenses)
	}
	if len(result.MatcherRuns) != 1 || result.MatcherRuns[0] != "acme.matcher.registry" {
		t.Fatalf("expected matcher run marker, got %#v", result.MatcherRuns)
	}
}

func fakeDetectorPluginSource(id string) string {
	return `package main

import (
	"context"
	"path/filepath"
	schemav1 "github.com/bomly-dev/bomly-cli/sdk"
)

type detector struct{}

func (d *detector) Metadata(ctx context.Context) (*schemav1.PluginMetadata, error) {
	return &schemav1.PluginMetadata{
		ID:               "` + id + `",
		Name:             "Fake Detector",
		Version:          "1.0.0",
		Kind:             schemav1.PluginKindDetector,
		PluginAPIVersion: schemav1.PluginAPIVersion,
	}, nil
}

func (d *detector) Descriptor(ctx context.Context) (*schemav1.DetectorDescriptor, error) {
	return &schemav1.DetectorDescriptor{
		Name:           "` + id + `",
		Enabled:        true,
		Origin:         schemav1.ExternalOrigin,
		Capabilities:   []string{"dependency-detection"},
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]schemav1.PackageManagerSupport, error) {
	return []schemav1.PackageManagerSupport{schemav1.Support(schemav1.PackageManagerGoMod, "go.mod")}, nil
}

func (d *detector) Ready(context.Context, *schemav1.DetectRequest) (*schemav1.ReadyResponse, error) {
	return &schemav1.ReadyResponse{Ready: true}, nil
}

func (d *detector) Applicable(context.Context, *schemav1.DetectRequest) (*schemav1.ApplicableResponse, error) {
	return &schemav1.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(ctx context.Context, req *schemav1.DetectRequest) (*schemav1.DetectResponse, error) {
	name := "example.com/demo"
	if req.ScopeFilter != schemav1.ScopeUnknown {
		name = "example.com/" + string(req.ScopeFilter)
	}
	packageNode := schemav1.NewDependencyWithID(name + "@v1.0.0", schemav1.Dependency{
		Ecosystem: string(schemav1.EcosystemGo),
		Name:      name,
		Version:   "v1.0.0",
		PURL:      "pkg:golang/" + name + "@v1.0.0",
	})
	graph := schemav1.New()
	if err := graph.AddNode(packageNode); err != nil {
		return nil, err
	}
	return &schemav1.DetectResponse{
		SubprojectInfo:      req.Subproject,
		RootExecutionTarget: req.ExecutionTarget,
		DetectorName:        "` + id + `",
		Origin:              schemav1.ExternalOrigin,
		Graphs: &schemav1.GraphContainer{
			Entries: []schemav1.GraphEntry{{
				Manifest: schemav1.ManifestMetadata{
					Path: filepath.Join(req.ProjectPath, "go.mod"),
					Kind: schemav1.ManifestKind("go.mod"),
				},
				Graph: graph,
			}},
		},
	}, nil
}

func main() {
	schemav1.ServeDetector(&detector{})
}
`
}

func fakeMatcherPluginSource(id string) string {
	return `package main

import (
	"context"
	"fmt"
	schemav1 "github.com/bomly-dev/bomly-cli/sdk"
)

type matcher struct{}

func (m *matcher) Metadata(ctx context.Context) (*schemav1.PluginMetadata, error) {
	return &schemav1.PluginMetadata{
		ID:               "` + id + `",
		Name:             "Fake Matcher",
		Version:          "1.0.0",
		Kind:             schemav1.PluginKindMatcher,
		PluginAPIVersion: schemav1.PluginAPIVersion,
	}, nil
}

func (m *matcher) Descriptor(ctx context.Context) (*schemav1.MatcherDescriptor, error) {
	return &schemav1.MatcherDescriptor{
		Name:           "` + id + `",
		Enabled:        true,
		Origin:         schemav1.ExternalOrigin,
	}, nil
}

func (m *matcher) Ready(context.Context, *schemav1.MatchRequest) (*schemav1.ReadyResponse, error) {
	return &schemav1.ReadyResponse{Ready: true}, nil
}

func (m *matcher) Applicable(context.Context, *schemav1.MatchRequest) (*schemav1.ApplicableResponse, error) {
	return &schemav1.ApplicableResponse{Applicable: true}, nil
}

func (m *matcher) Match(ctx context.Context, req *schemav1.MatchRequest) (*schemav1.MatchResponse, error) {
	if req.Registry == nil {
		return nil, fmt.Errorf("registry is nil")
	}
	pkg, ok := req.Registry.Get("pkg:npm/react@18.2.0")
	if !ok || pkg == nil {
		return nil, fmt.Errorf("expected registry package")
	}
	pkg.Licenses = []schemav1.PackageLicense{{SPDXExpression: "MIT"}}
	return &schemav1.MatchResponse{
		Registry:    req.Registry,
		MatcherRuns: []string{"` + id + `"},
	}, nil
}

func main() {
	schemav1.ServeMatcher(&matcher{})
}
`
}

func fakeDetectorPluginSourceWithoutPackageManagers(id string) string {
	return `package main

import (
	"context"
	schemav1 "github.com/bomly-dev/bomly-cli/sdk"
)

type detector struct{}

func (d *detector) Metadata(ctx context.Context) (*schemav1.PluginMetadata, error) {
	return &schemav1.PluginMetadata{
		ID:               "` + id + `",
		Name:             "Invalid Detector",
		Version:          "1.0.0",
		Kind:             schemav1.PluginKindDetector,
		PluginAPIVersion: schemav1.PluginAPIVersion,
	}, nil
}

func (d *detector) Descriptor(ctx context.Context) (*schemav1.DetectorDescriptor, error) {
	return &schemav1.DetectorDescriptor{
		Name:           "` + id + `",
		Enabled:        true,
		Origin:         schemav1.ExternalOrigin,
		Capabilities:   []string{"dependency-detection"},
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]schemav1.PackageManagerSupport, error) {
	return nil, nil
}

func (d *detector) Ready(context.Context, *schemav1.DetectRequest) (*schemav1.ReadyResponse, error) {
	return &schemav1.ReadyResponse{Ready: true}, nil
}

func (d *detector) Applicable(context.Context, *schemav1.DetectRequest) (*schemav1.ApplicableResponse, error) {
	return &schemav1.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(ctx context.Context, req *schemav1.DetectRequest) (*schemav1.DetectResponse, error) {
	return &schemav1.DetectResponse{}, nil
}

func main() {
	schemav1.ServeDetector(&detector{})
}
`
}

func executableName(base string) string {
	if filepath.Ext(base) == ".exe" {
		return base
	}
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}
