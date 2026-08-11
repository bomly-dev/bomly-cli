package plugin_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/internal/testutil"
	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
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
	if result.Manifest.ID != "acme.analyzer.reach" || result.Manifest.Kind != sdk.PluginKindAnalyzer {
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
	analyzers := reg.Analyzers(sdk.AnalyzeRequest{
		AnalyzerFilter: sdk.AnalyzerFilter{Include: []string{"acme.analyzer.reach"}},
	})
	if len(analyzers) != 1 {
		t.Fatalf("expected one external analyzer, got %d", len(analyzers))
	}
	descriptor := analyzers[0].Descriptor()
	if len(descriptor.SupportedLanguages) != 1 || descriptor.SupportedLanguages[0] != sdk.LanguageGo {
		t.Fatalf("expected analyzer descriptor languages, got %#v", descriptor)
	}

	// The fake analyzer returns PackageUpdates only (no full registry); the
	// host must merge them into the request registry.
	const purl = "pkg:golang/example.com/demo@v1.0.0"
	registry := sdk.NewPackageRegistry()
	registry.Ensure(purl).Name = "demo"
	analysis, err := analyzers[0].Analyze(context.Background(), sdk.AnalyzeRequest{Registry: registry})
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
	schemav1 "github.com/bomly-dev/bomly-sdk"
)

type analyzer struct{}

func (a *analyzer) Descriptor(context.Context) (*schemav1.AnalyzerDescriptor, error) {
	return &schemav1.AnalyzerDescriptor{
		Name:               "` + id + `",
		Tags:               []string{"reachability"},
		SupportedLanguages: []schemav1.Language{schemav1.LanguageGo},
		SupportedTiers:     []schemav1.ReachabilityTier{schemav1.TierSymbol},
		Capabilities:       []string{schemav1.CapabilityPackageUpdates},
	}, nil
}

func (a *analyzer) Ready(context.Context, *schemav1.AnalyzeRequest) (*schemav1.ReadyResponse, error) {
	return &schemav1.ReadyResponse{Ready: true}, nil
}

func (a *analyzer) Applicable(context.Context, *schemav1.AnalyzeRequest) (*schemav1.ApplicableResponse, error) {
	return &schemav1.ApplicableResponse{Applicable: true}, nil
}

func (a *analyzer) Analyze(ctx context.Context, req *schemav1.AnalyzeRequest) (*schemav1.AnalyzeResponse, error) {
	if !req.AcceptPackageUpdates {
		return nil, fmt.Errorf("host did not advertise package-update support")
	}
	update := &schemav1.Package{
		Coordinates: schemav1.Coordinates{PURL: "pkg:golang/example.com/demo@v1.0.0"},
		Vulnerabilities: []schemav1.Vulnerability{{
			ID: "GO-2026-0001",
			Reachability: &schemav1.Reachability{
				Status: schemav1.ReachabilityReachable,
				Tier:   schemav1.TierSymbol,
			},
		}},
	}
	return &schemav1.AnalyzeResponse{
		PackageUpdates: []*schemav1.Package{update},
		AnalyzerRuns:   []string{"` + id + `"},
	}, nil
}

func main() {
	schemav1.ServeAnalyzer(&analyzer{})
}
`
}
