package diff

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func TestRun_ComputesAuditDeltas(t *testing.T) {
	basePkg := sdk.NewPackageWithID("pkg:npm/react@18.2.0", sdk.Package{Name: "react", Version: "18.2.0", PURL: "pkg:npm/react@18.2.0"})
	headPkg := sdk.NewPackageWithID("pkg:npm/react@18.2.0", sdk.Package{Name: "react", Version: "18.2.0", PURL: "pkg:npm/react@18.2.0"})
	base := diffTestPipeline(t, basePkg, []sdk.Finding{{ID: "CVE-1", Kind: sdk.FindingKindVulnerability, Source: "osv", Package: basePkg}})
	head := diffTestPipeline(t, headPkg, []sdk.Finding{
		{ID: "CVE-1", Kind: sdk.FindingKindVulnerability, Source: "osv", Package: headPkg},
		{ID: "CVE-2", Kind: sdk.FindingKindVulnerability, Source: "osv", Package: headPkg},
	})

	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: base, Request: diffTestRequest()},
		Head: Target{Pipeline: head, Request: diffTestRequest()},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Audit == nil {
		t.Fatal("expected diff audit")
	}
	if len(result.Audit.Introduced) != 1 || result.Audit.Introduced[0].ID != "CVE-2" {
		t.Fatalf("expected CVE-2 introduced, got %#v", result.Audit.Introduced)
	}
	if len(result.Audit.Persisted) != 1 || result.Audit.Persisted[0].ID != "CVE-1" {
		t.Fatalf("expected CVE-1 persisted, got %#v", result.Audit.Persisted)
	}
	if len(result.Audit.Resolved) != 0 {
		t.Fatalf("expected no resolved findings, got %#v", result.Audit.Resolved)
	}
}

func diffTestPipeline(t *testing.T, pkg *sdk.Package, findings []sdk.Finding) *engine.Pipeline {
	t.Helper()
	registry := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	g := sdk.New()
	if err := g.AddPackage(pkg); err != nil {
		t.Fatalf("add package: %v", err)
	}
	registry.RegisterDetector(fakeDetector{
		descriptor: sdk.DetectorDescriptor{
			Name:                "npm-detector",
			Enabled:             true,
			SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemNPM},
			SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerNPM},
			SupportedModes:      []sdk.TargetMode{sdk.TargetModeFullGraph},
		},
		result: sdk.DetectionResult{
			Graphs: engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
		},
	})
	registry.RegisterAuditor(fakeAuditor{
		descriptor: sdk.AuditorDescriptor{Name: "severity-policy", Enabled: true, SupportedModes: []sdk.TargetMode{sdk.TargetModeFullGraph}},
		result:     sdk.AuditResult{Findings: findings},
	})
	return engine.NewPipeline(registry, zap.NewNop())
}

func diffTestRequest() engine.PipelineRequest {
	return engine.PipelineRequest{
		Subprojects: []sdk.Subproject{{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		}},
		AuditEnabled: true,
	}
}

type fakeDetector struct {
	descriptor sdk.DetectorDescriptor
	result     sdk.DetectionResult
}

func (f fakeDetector) Descriptor() sdk.DetectorDescriptor {
	return f.descriptor
}

func (f fakeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return nil
}

func (f fakeDetector) Ready() bool {
	return true
}

func (f fakeDetector) Applicable(context.Context, sdk.DetectionRequest) (bool, error) {
	return true, nil
}

func (f fakeDetector) ResolveGraph(context.Context, sdk.DetectionRequest) (sdk.DetectionResult, error) {
	return f.result, nil
}

type fakeAuditor struct {
	descriptor sdk.AuditorDescriptor
	result     sdk.AuditResult
}

func (f fakeAuditor) Descriptor() sdk.AuditorDescriptor {
	return f.descriptor
}

func (f fakeAuditor) Ready() bool {
	return true
}

func (f fakeAuditor) Applicable(context.Context, sdk.AuditRequest) (bool, error) {
	return true, nil
}

func (f fakeAuditor) Audit(context.Context, sdk.AuditRequest) (sdk.AuditResult, error) {
	return f.result, nil
}
