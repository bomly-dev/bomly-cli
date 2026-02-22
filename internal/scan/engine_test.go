package scan

import (
	"context"
	"errors"
	"testing"
)

type fakeDetector struct {
	descriptor DetectorDescriptor
	result     ResolveGraphResult
	err        error
	ready      *bool
	applicable *bool
	applyErr   error
	onResolve  func(ResolveGraphRequest)
}

func (f fakeDetector) Descriptor() DetectorDescriptor { return f.descriptor }

func (f fakeDetector) ResolveGraph(_ context.Context, req ResolveGraphRequest) (ResolveGraphResult, error) {
	if f.onResolve != nil {
		f.onResolve(req)
	}
	return f.result, f.err
}

func (f fakeDetector) Ready() bool {
	if f.ready == nil {
		return true
	}
	return *f.ready
}

func (f fakeDetector) Applicable(_ context.Context, _ ResolveGraphRequest) (bool, error) {
	if f.applyErr != nil {
		return false, f.applyErr
	}
	if f.applicable == nil {
		return true, nil
	}
	return *f.applicable, nil
}

type fakeAuditor struct {
	descriptor AuditorDescriptor
	result     AuditResult
	err        error
	ready      *bool
	applicable *bool
	applyErr   error
}

func (f fakeAuditor) Descriptor() AuditorDescriptor { return f.descriptor }

func (f fakeAuditor) Audit(_ context.Context, _ AuditRequest) (AuditResult, error) {
	return f.result, f.err
}

func (f fakeAuditor) Ready() bool {
	if f.ready == nil {
		return true
	}
	return *f.ready
}

func (f fakeAuditor) Applicable(_ context.Context, _ AuditRequest) (bool, error) {
	if f.applyErr != nil {
		return false, f.applyErr
	}
	if f.applicable == nil {
		return true, nil
	}
	return *f.applicable, nil
}

func TestEngineAudit_AggregatesAuditorResults(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "a", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}, SupportedModes: []TargetMode{TargetModeFullGraph}, Priority: 10},
		result:     AuditResult{Findings: []Finding{{ID: "1"}}},
	})
	registry.RegisterAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "b", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}, SupportedModes: []TargetMode{TargetModeFullGraph}, Priority: 20},
		result:     AuditResult{Findings: []Finding{{ID: "2"}}, RiskScores: []RiskScore{{Score: 50}}},
	})

	engine := NewEngine(registry)
	result, err := engine.Audit(context.Background(), AuditRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Mode: TargetModeFullGraph})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	if len(result.RiskScores) != 1 {
		t.Fatalf("expected 1 risk score, got %d", len(result.RiskScores))
	}
}

func TestEngineAudit_ReturnsPartialResultsWhenAnAuditorFails(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "working", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}, SupportedModes: []TargetMode{TargetModeFullGraph}, Priority: 20},
		result:     AuditResult{Findings: []Finding{{ID: "1"}}},
	})
	registry.RegisterAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "broken", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}, SupportedModes: []TargetMode{TargetModeFullGraph}, Priority: 10},
		err:        errors.New("boom"),
	})

	engine := NewEngine(registry)
	result, err := engine.Audit(context.Background(), AuditRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Mode: TargetModeFullGraph})
	if err == nil {
		t.Fatal("expected joined error")
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "1" {
		t.Fatalf("expected partial findings to be preserved, got %#v", result.Findings)
	}
}

func TestEngineAudit_SkipsNotReadyOrNotApplicableAuditors(t *testing.T) {
	registry := NewRegistry()
	notReady := false
	notApplicable := false
	registry.RegisterAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "not-ready", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}, SupportedModes: []TargetMode{TargetModeFullGraph}, Priority: 30},
		ready:      &notReady,
	})
	registry.RegisterAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "not-applicable", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}, SupportedModes: []TargetMode{TargetModeFullGraph}, Priority: 20},
		applicable: &notApplicable,
	})
	registry.RegisterAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "usable", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}, SupportedModes: []TargetMode{TargetModeFullGraph}, Priority: 10},
		result:     AuditResult{Findings: []Finding{{ID: "1"}}},
	})

	engine := NewEngine(registry)
	result, err := engine.Audit(context.Background(), AuditRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Mode: TargetModeFullGraph})
	if err == nil {
		t.Fatal("expected joined error for skipped auditors")
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "1" {
		t.Fatalf("expected applicable ready auditor result, got %#v", result.Findings)
	}
}
