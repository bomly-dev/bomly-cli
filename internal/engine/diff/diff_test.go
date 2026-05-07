package diff

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func TestRun_ComputesAuditDeltas(t *testing.T) {
	basePkg := model.NewPackageWithID("pkg:npm/react@18.2.0", model.Package{Name: "react", Version: "18.2.0", PURL: "pkg:npm/react@18.2.0"})
	headPkg := model.NewPackageWithID("pkg:npm/react@18.2.0", model.Package{Name: "react", Version: "18.2.0", PURL: "pkg:npm/react@18.2.0"})
	base := diffTestPipeline(t, basePkg, []model.Finding{{ID: "CVE-1", Kind: model.FindingKindVulnerability, Source: "osv", Package: basePkg}})
	head := diffTestPipeline(t, headPkg, []model.Finding{
		{ID: "CVE-1", Kind: model.FindingKindVulnerability, Source: "osv", Package: headPkg},
		{ID: "CVE-2", Kind: model.FindingKindVulnerability, Source: "osv", Package: headPkg},
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

func diffTestPipeline(t *testing.T, pkg *model.Package, findings []model.Finding) *engine.Pipeline {
	t.Helper()
	registry := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	g := model.New()
	if err := g.AddPackage(pkg); err != nil {
		t.Fatalf("add package: %v", err)
	}
	registry.RegisterDetector(fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:                "npm-detector",
			Enabled:             true,
			SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM},
			SupportedManagers:   []model.PackageManager{model.PackageManagerNPM},
			SupportedModes:      []model.TargetMode{model.TargetModeFullGraph},
		},
		result: model.DetectionResult{
			Graphs: engine.SingleGraphContainer(g, model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
		},
	})
	registry.RegisterAuditor(fakeAuditor{
		descriptor: model.AuditorDescriptor{Name: "severity-policy", Enabled: true, SupportedModes: []model.TargetMode{model.TargetModeFullGraph}},
		result:     model.AuditResult{Findings: findings},
	})
	return engine.NewPipeline(registry, zap.NewNop())
}

func diffTestRequest() engine.PipelineRequest {
	return engine.PipelineRequest{
		Subprojects: []model.Subproject{{
			ExecutionTarget:         model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		}},
		AuditEnabled: true,
	}
}

type fakeDetector struct {
	descriptor model.DetectorDescriptor
	result     model.DetectionResult
}

func (f fakeDetector) Descriptor() model.DetectorDescriptor {
	return f.descriptor
}

func (f fakeDetector) PackageManagerSupport() []model.PackageManagerSupport {
	return nil
}

func (f fakeDetector) Ready() bool {
	return true
}

func (f fakeDetector) Applicable(context.Context, model.DetectionRequest) (bool, error) {
	return true, nil
}

func (f fakeDetector) ResolveGraph(context.Context, model.DetectionRequest) (model.DetectionResult, error) {
	return f.result, nil
}

type fakeAuditor struct {
	descriptor model.AuditorDescriptor
	result     model.AuditResult
}

func (f fakeAuditor) Descriptor() model.AuditorDescriptor {
	return f.descriptor
}

func (f fakeAuditor) Ready() bool {
	return true
}

func (f fakeAuditor) Applicable(context.Context, model.AuditRequest) (bool, error) {
	return true, nil
}

func (f fakeAuditor) Audit(context.Context, model.AuditRequest) (model.AuditResult, error) {
	return f.result, nil
}
