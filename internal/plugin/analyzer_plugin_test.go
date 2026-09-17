package plugin_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	testutil "github.com/bomly-dev/bomly-sdk/testkit"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestInstallDevBinaryDiscoversAnalyzerRoleAndRunsIt(t *testing.T) {
	root := t.TempDir()
	binaryPath := filepath.Join(t.TempDir(), executableName("bomly-plugin-analyzer"))
	if err := testutil.BuildGoBinary(t, binaryPath, fakeAnalyzerPluginSource("acme.analyzer.reach")); err != nil {
		t.Fatalf("build fake analyzer plugin: %v", err)
	}

	result, err := managedplugin.Install(context.Background(), root, binaryPath, managedplugin.InstallOptions{DevBinary: true})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if result.Manifest.ID != "acme.analyzer.reach" || result.Manifest.Kind != plugin.PluginKindAnalyzer {
		t.Fatalf("expected analyzer role discovery, got %#v", result.Manifest)
	}

	if _, err := managedplugin.Verify(context.Background(), root, "acme.analyzer.reach"); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	testResult, err := managedplugin.Test(context.Background(), root, "acme.analyzer.reach", nil)
	if err != nil {
		t.Fatalf("Test() error = %v", err)
	}
	if !testResult.Ready || testResult.Probe != "analyzer-ready" {
		t.Fatalf("expected analyzer readiness probe, got %#v", testResult)
	}

	if _, err := managedplugin.Enable(root, "acme.analyzer.reach"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}

	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	if err := managedplugin.RegisterRuntimePlugins(context.Background(), reg, root); err != nil {
		t.Fatalf("RegisterRuntimePlugins() error = %v", err)
	}
	analyzers := reg.Analyzers(plugin.AnalyzeRequest{
		AnalyzerFilter: plugin.AnalyzerFilter{Include: []string{"acme.analyzer.reach"}},
	})
	if len(analyzers) != 1 {
		t.Fatalf("expected one external analyzer, got %d", len(analyzers))
	}
	descriptor := analyzers[0].Descriptor()
	if len(descriptor.SupportedLanguages) != 1 || descriptor.SupportedLanguages[0] != model.LanguageGo {
		t.Fatalf("expected analyzer descriptor languages, got %#v", descriptor)
	}

	// The fake analyzer returns PackageUpdates only (no full registry); the
	// host must merge them into the request registry.
	const purl = "pkg:golang/example.com/demo@v1.0.0"
	registry := model.NewPackageRegistry()
	registry.Ensure(purl).Name = "demo"
	analysis, err := analyzers[0].Analyze(context.Background(), plugin.AnalyzeRequest{Registry: registry})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if analysis.Registry == nil {
		t.Fatal("expected analyzer result registry")
	}
	pkg, ok := analysis.Registry.Get(purl)
	if !ok || len(pkg.Vulnerabilities) != 1 || pkg.Vulnerabilities[0].Reachability == nil {
		t.Fatalf("expected package-update merge to annotate reachability, got %#v", pkg)
	}
}

func fakeAnalyzerPluginSource(id string) string {
	return `package main

import (
	"context"
	"fmt"
	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
	"github.com/bomly-dev/bomly-sdk/runtime"
)

type analyzer struct{}

func (a *analyzer) Descriptor(context.Context) (*plugin.AnalyzerDescriptor, error) {
	return &plugin.AnalyzerDescriptor{
		Name:               "` + id + `",
		Tags:               []string{"reachability"},
		SupportedLanguages: []model.Language{model.LanguageGo},
		SupportedTiers:     []model.ReachabilityTier{model.TierSymbol},
		Capabilities:       []string{plugin.CapabilityPackageUpdates},
	}, nil
}

func (a *analyzer) Ready(context.Context, *plugin.AnalyzeRequest) (*plugin.ReadyResponse, error) {
	return &plugin.ReadyResponse{Ready: true}, nil
}

func (a *analyzer) Applicable(context.Context, *plugin.AnalyzeRequest) (*plugin.ApplicableResponse, error) {
	return &plugin.ApplicableResponse{Applicable: true}, nil
}

func (a *analyzer) Analyze(ctx context.Context, req *plugin.AnalyzeRequest) (*plugin.AnalyzeResponse, error) {
	if !req.AcceptPackageUpdates {
		return nil, fmt.Errorf("host did not advertise package-update support")
	}
	update := &model.Package{
		Coordinates: model.Coordinates{PURL: "pkg:golang/example.com/demo@v1.0.0"},
		Vulnerabilities: []model.Vulnerability{{
			ID: "GO-2026-0001",
			Reachability: &model.Reachability{
				Status: model.ReachabilityReachable,
				Tier:   model.TierSymbol,
			},
		}},
	}
	return &plugin.AnalyzeResponse{
		PackageUpdates: []*model.Package{update},
		AnalyzerRuns:   []string{"` + id + `"},
	}, nil
}

func main() {
	runtime.ServeAnalyzer(&analyzer{})
}
`
}
