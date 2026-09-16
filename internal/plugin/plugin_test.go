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
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	testutil "github.com/bomly-dev/bomly-sdk/testkit"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
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
	disabledRegistry := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	disabledRegistry.Build()
	if err := managedplugin.RegisterRuntimePlugins(context.Background(), disabledRegistry, root); err != nil {
		t.Fatalf("RegisterRuntimePlugins() with disabled plugin error = %v", err)
	}
	for _, detector := range disabledRegistry.AllDetectors() {
		if detector.Descriptor().Name == "acme.detector.fake" {
			t.Fatal("disabled external plugin joined the runtime registry")
		}
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
	if got := installed[0].DetectorDescriptor.SupportedManagers; len(got) != 1 || got[0] != model.PackageManagerGoMod {
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
	if err == nil ||
		(!strings.Contains(err.Error(), "escapes the extraction directory") &&
			!strings.Contains(err.Error(), "parent-directory component")) {
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
	if err == nil || !strings.Contains(err.Error(), "detector plugin runtime snapshot must include detector descriptor and package manager support") {
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
		DetectorFilter:  plugin.DetectorFilter{Include: []string{"acme.detector.gomod"}},
		EcosystemFilter: model.EcosystemFilter{Include: []model.Ecosystem{model.EcosystemGo}},
	})
	subprojects, err := opts.PlanSubprojects(filtered, opts.Request{
		Registry:        reg,
		ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetFilesystem, Location: projectDir},
		DetectorFilter:  plugin.DetectorFilter{Include: []string{"acme.detector.gomod"}},
		EcosystemFilter: model.EcosystemFilter{Include: []model.Ecosystem{model.EcosystemGo}},
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

	detectors := filtered.PlannedDetectors(plugin.DetectionRequest{
		ProjectPath:     projectDir,
		ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetFilesystem, Location: projectDir},
		Subproject:      subprojects[0],
		Ecosystem:       model.EcosystemGo,
		PackageManager:  model.PackageManagerGoMod,
	}, []string{"acme.detector.gomod"})
	if len(detectors) != 1 {
		t.Fatalf("expected one planned detector, got %d", len(detectors))
	}
	result, err := detectors[0].ResolveGraph(context.Background(), plugin.DetectionRequest{
		ProjectPath:     projectDir,
		ExecutionTarget: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetFilesystem, Location: projectDir},
		Subproject:      subprojects[0],
		Ecosystem:       model.EcosystemGo,
		PackageManager:  model.PackageManagerGoMod,
		ScopeFilter:     model.ScopeRuntime,
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
	if _, ok := testnodes.Find(graph, "example.com/runtime@v1.0.0"); !ok {
		t.Fatalf("expected plugin detector to receive runtime scope, got %s", graph.PrettyString())
	}
	if len(detectors[0].Descriptor().RemediationCapabilities) != 0 {
		t.Fatalf("legacy detector unexpectedly advertises remediation: %#v", detectors[0].Descriptor())
	}
	provider, ok := detectors[0].(plugin.DetectorRemediationProvider)
	if !ok {
		t.Fatalf("external detector wrapper does not implement optional provider: %T", detectors[0])
	}
	hints, err := provider.RemediationHints(context.Background(), plugin.RemediationHintRequest{})
	if err != nil || len(hints.Hints) != 0 {
		t.Fatalf("legacy detector remediation call = %#v, %v", hints, err)
	}
}

func TestExternalDetectorProvidesAdvertisedRemediationHints(t *testing.T) {
	root := t.TempDir()
	binaryPath := filepath.Join(t.TempDir(), executableName("bomly-plugin-remediation"))
	if err := testutil.BuildGoBinary(t, binaryPath, fakeRemediationDetectorPluginSource("acme.detector.remediation")); err != nil {
		t.Fatalf("build fake remediation plugin: %v", err)
	}
	if _, err := managedplugin.Install(context.Background(), root, binaryPath, managedplugin.InstallOptions{DevBinary: true}); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if _, err := managedplugin.Enable(root, "acme.detector.remediation"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}

	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	if err := managedplugin.RegisterRuntimePlugins(context.Background(), reg, root); err != nil {
		t.Fatalf("RegisterRuntimePlugins() error = %v", err)
	}
	var detector plugin.Detector
	for _, candidate := range reg.AllDetectors() {
		if candidate.Descriptor().Name == "acme.detector.remediation" {
			detector = candidate
			break
		}
	}
	if detector == nil {
		t.Fatal("external remediation detector was not registered")
	}
	provider, ok := detector.(plugin.DetectorRemediationProvider)
	if !ok {
		t.Fatalf("registered detector does not implement DetectorRemediationProvider: %T", detector)
	}
	response, err := provider.RemediationHints(context.Background(), plugin.RemediationHintRequest{})
	if err != nil {
		t.Fatalf("RemediationHints() error = %v", err)
	}
	if len(response.Hints) != 1 ||
		response.Hints[0].DependencyRef != "example.com/demo@v1.0.0" ||
		len(response.Hints[0].Strategies) != 1 ||
		response.Hints[0].Strategies[0].Action != model.RemediationActionLockfileRefresh {
		t.Fatalf("RemediationHints() = %#v", response)
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

	// Register through a persistent subprocess pool so the external matcher
	// exercises the pooled launch path end to end.
	pool := managedplugin.NewClientPool()
	defer pool.Shutdown()
	launchCtx := managedplugin.WithLaunchOptions(context.Background(), managedplugin.LaunchOptions{Pool: pool})

	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	if err := managedplugin.RegisterRuntimePlugins(launchCtx, reg, root); err != nil {
		t.Fatalf("RegisterRuntimePlugins() error = %v", err)
	}
	matchers := reg.Matchers(plugin.MatchRequest{
		MatcherFilter: plugin.MatcherFilter{Include: []string{"acme.matcher.registry"}},
	})
	if len(matchers) != 1 {
		t.Fatalf("expected one external matcher, got %d", len(matchers))
	}

	if err := matchers[0].Ready(context.Background(), plugin.MatchRequest{}); err != nil {
		t.Fatalf("Ready() through pooled subprocess error = %v", err)
	}

	const purl = "pkg:npm/react@18.2.0"
	registry := model.NewPackageRegistry()
	registry.Ensure(purl).Name = "react"
	result, err := matchers[0].Match(context.Background(), plugin.MatchRequest{
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
	if result.MatcherStats.Name != "acme.matcher.registry" || result.MatcherStats.Licenses != 1 {
		t.Fatalf("expected matcher stats marker, got %#v", result.MatcherStats)
	}
}

func fakeDetectorPluginSource(id string) string {
	return `package main

import (
	"context"
	"path/filepath"
	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
	"github.com/bomly-dev/bomly-sdk/runtime"
)

type detector struct{}

func (d *detector) Descriptor(ctx context.Context) (*plugin.DetectorDescriptor, error) {
	return &plugin.DetectorDescriptor{
		Name:           "` + id + `",
		Tags:   []string{"dependency-detection"},
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]plugin.PackageManagerSupport, error) {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerGoMod, "go.mod")}, nil
}

func (d *detector) Ready(context.Context, *plugin.DetectRequest) (*plugin.ReadyResponse, error) {
	return &plugin.ReadyResponse{Ready: true}, nil
}

func (d *detector) Applicable(context.Context, *plugin.DetectRequest) (*plugin.ApplicableResponse, error) {
	return &plugin.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(ctx context.Context, req *plugin.DetectRequest) (*plugin.DetectResponse, error) {
	name := "example.com/demo"
	if req.ScopeFilter != model.ScopeUnknown {
		name = "example.com/" + string(req.ScopeFilter)
	}
	packageNode, err := model.NewDependencyNode(model.Coordinates{
		Ecosystem: model.EcosystemGo,
		Name:      name,
		Version:   "v1.0.0",
		PURL:      "pkg:golang/" + name + "@v1.0.0",
	})
	if err != nil {
		return nil, err
	}
	graph := model.New()
	if err := graph.AddNode(packageNode); err != nil {
		return nil, err
	}
	return &plugin.DetectResponse{
		SubprojectInfo:      req.Subproject,
		RootExecutionTarget: req.ExecutionTarget,
		DetectorName:        "` + id + `",
		Graphs: &model.GraphContainer{
			Entries: []model.GraphEntry{{
				Manifest: model.ManifestMetadata{
					Path: filepath.Join(req.ProjectPath, "go.mod"),
					Kind: model.ManifestKind("go.mod"),
				},
				Graph: graph,
			}},
		},
	}, nil
}

func main() {
	runtime.ServeDetector(&detector{})
}
`
}

func fakeMatcherPluginSource(id string) string {
	return `package main

import (
	"context"
	"fmt"
	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
	"github.com/bomly-dev/bomly-sdk/runtime"
)

type matcher struct{}

func (m *matcher) Descriptor(ctx context.Context) (*plugin.MatcherDescriptor, error) {
	return &plugin.MatcherDescriptor{
		Name:           "` + id + `",
	}, nil
}

func (m *matcher) Ready(context.Context, *plugin.MatchRequest) (*plugin.ReadyResponse, error) {
	return &plugin.ReadyResponse{Ready: true}, nil
}

func (m *matcher) Applicable(context.Context, *plugin.MatchRequest) (*plugin.ApplicableResponse, error) {
	return &plugin.ApplicableResponse{Applicable: true}, nil
}

func (m *matcher) Match(ctx context.Context, req *plugin.MatchRequest) (*plugin.MatchResponse, error) {
	if req.Registry == nil {
		return nil, fmt.Errorf("registry is nil")
	}
	pkg, ok := req.Registry.Get("pkg:npm/react@18.2.0")
	if !ok || pkg == nil {
		return nil, fmt.Errorf("expected registry package")
	}
	pkg.Licenses = []model.PackageLicense{{SPDXExpression: "MIT"}}
	return &plugin.MatchResponse{
		Registry: req.Registry,
		MatcherStats: plugin.MatcherStats{
			Name: "` + id + `",
			MatchedPackages: 1,
			Licenses: 1,
		},
	}, nil
}

func main() {
	runtime.ServeMatcher(&matcher{})
}
`
}

func fakeDetectorPluginSourceWithoutPackageManagers(id string) string {
	return `package main

import (
	"context"
	"github.com/bomly-dev/bomly-sdk/plugin"
	"github.com/bomly-dev/bomly-sdk/runtime"
)

type detector struct{}

func (d *detector) Descriptor(ctx context.Context) (*plugin.DetectorDescriptor, error) {
	return &plugin.DetectorDescriptor{
		Name:           "` + id + `",
		Tags:   []string{"dependency-detection"},
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]plugin.PackageManagerSupport, error) {
	return nil, nil
}

func (d *detector) Ready(context.Context, *plugin.DetectRequest) (*plugin.ReadyResponse, error) {
	return &plugin.ReadyResponse{Ready: true}, nil
}

func (d *detector) Applicable(context.Context, *plugin.DetectRequest) (*plugin.ApplicableResponse, error) {
	return &plugin.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(ctx context.Context, req *plugin.DetectRequest) (*plugin.DetectResponse, error) {
	return &plugin.DetectResponse{}, nil
}

func main() {
	runtime.ServeDetector(&detector{})
}
`
}

func fakeRemediationDetectorPluginSource(id string) string {
	return `package main

import (
	"context"
	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
	"github.com/bomly-dev/bomly-sdk/runtime"
)

type detector struct{}

func (d *detector) Descriptor(context.Context) (*plugin.DetectorDescriptor, error) {
	return &plugin.DetectorDescriptor{
		Name: "` + id + `",
		Tags: []string{"dependency-detection"},
		RemediationCapabilities: []plugin.RemediationCapability{{
			SupportedManagers: []model.PackageManager{model.PackageManagerGoMod},
			Actions: []model.RemediationAction{model.RemediationActionLockfileRefresh},
		}},
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]plugin.PackageManagerSupport, error) {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerGoMod, "go.mod")}, nil
}

func (d *detector) Ready(context.Context, *plugin.DetectRequest) (*plugin.ReadyResponse, error) {
	return &plugin.ReadyResponse{Ready: true}, nil
}

func (d *detector) Applicable(context.Context, *plugin.DetectRequest) (*plugin.ApplicableResponse, error) {
	return &plugin.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(context.Context, *plugin.DetectRequest) (*plugin.DetectResponse, error) {
	return &plugin.DetectResponse{}, nil
}

func (d *detector) RemediationHints(
	context.Context,
	*plugin.RemediationHintRequest,
) (*plugin.RemediationHintResponse, error) {
	return &plugin.RemediationHintResponse{Hints: []plugin.RemediationHint{{
		DependencyRef: "example.com/demo@v1.0.0",
		ManifestPath: "go.mod",
		Strategies: []plugin.RemediationStrategyHint{{
			Action: model.RemediationActionLockfileRefresh,
			Advice: "refresh go.sum",
		}},
	}}}, nil
}

func main() {
	runtime.ServeDetector(&detector{})
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
