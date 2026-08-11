package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

type fakeDetector struct {
	descriptor  DetectorDescriptor
	result      ResolveGraphResult
	err         error
	ready       *bool
	readyReason string
	applicable  *bool
	applyErr    error
	onResolve   func(ResolveGraphRequest)
}

func (f fakeDetector) Descriptor() DetectorDescriptor { return f.descriptor }

func (f fakeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	values := make([]sdk.PackageManagerSupport, 0, len(f.descriptor.SupportedManagers))
	for _, manager := range f.descriptor.SupportedManagers {
		values = append(values, sdk.Support(manager))
	}
	return values
}

func (f fakeDetector) ResolveGraph(_ context.Context, req ResolveGraphRequest) (ResolveGraphResult, error) {
	if f.onResolve != nil {
		f.onResolve(req)
	}
	return f.result, f.err
}

func (f fakeDetector) Ready(context.Context, ResolveGraphRequest) error {
	if f.ready != nil && !*f.ready {
		if f.readyReason != "" {
			return errors.New(f.readyReason)
		}
		return errors.New("not ready")
	}
	return nil
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

type fakeInstallFirstDetector struct {
	fakeDetector
	installed bool
	onInstall func(ResolveGraphRequest)
}

func (f *fakeInstallFirstDetector) Install(_ context.Context, req ResolveGraphRequest) error {
	f.installed = true
	if f.onInstall != nil {
		f.onInstall(req)
	}
	return nil
}

type fakeAuditor struct {
	descriptor   AuditorDescriptor
	result       AuditResult
	err          error
	ready        *bool
	applicable   *bool
	applyErr     error
	run          func(AuditRequest) AuditResult
	onReady      func(AuditRequest)
	onApplicable func(AuditRequest)
}

func (f fakeAuditor) Descriptor() AuditorDescriptor { return f.descriptor }

func (f fakeAuditor) Audit(_ context.Context, req AuditRequest) (AuditResult, error) {
	if f.run != nil {
		return f.run(req), f.err
	}
	return f.result, f.err
}

func (f fakeAuditor) Ready(_ context.Context, req AuditRequest) error {
	if f.onReady != nil {
		f.onReady(req)
	}
	if f.ready != nil && !*f.ready {
		return errors.New("not ready")
	}
	return nil
}

func (f fakeAuditor) Applicable(_ context.Context, req AuditRequest) (bool, error) {
	if f.onApplicable != nil {
		f.onApplicable(req)
	}
	if f.applyErr != nil {
		return false, f.applyErr
	}
	if f.applicable == nil {
		return true, nil
	}
	return *f.applicable, nil
}

func TestEngineAudit_AggregatesAuditorResults(t *testing.T) {
	registry := newTestRegistry()
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "a", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     AuditResult{Findings: []Finding{{ID: "1"}}},
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "b", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     AuditResult{Findings: []Finding{{ID: "2"}}, RiskScores: []RiskScore{{Score: 50}}},
	})

	engine := NewEngine(registry)
	result, err := engine.Audit(context.Background(), AuditRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM})
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
	registry := newTestRegistry()
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "working", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     AuditResult{Findings: []Finding{{ID: "1"}}},
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "broken", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		err:        errors.New("boom"),
	})

	engine := NewEngine(registry)
	result, err := engine.Audit(context.Background(), AuditRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM})
	if err == nil {
		t.Fatal("expected joined error")
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "1" {
		t.Fatalf("expected partial findings to be preserved, got %#v", result.Findings)
	}
}

func TestEngineAudit_ClonesDependencyDetailChangesPerAuditor(t *testing.T) {
	before := sdk.NewDependencyWithID("before", sdk.Dependency{Source: sdk.DependencySourceRegistry})
	after := sdk.NewDependencyWithID("after", sdk.Dependency{Source: sdk.DependencySourceGit})
	request := AuditRequest{
		Ecosystem:      EcosystemNPM,
		PackageManager: PackageManagerNPM,
		DependencyDetailChanges: []sdk.DependencyDetailTransition{{
			Before:        before,
			After:         after,
			ChangedFields: []sdk.DependencyDetailField{sdk.DependencyDetailSource},
		}},
	}
	assertOriginal := func(phase string, req AuditRequest) {
		t.Helper()
		if req.DependencyDetailChanges[0].After.Source != sdk.DependencySourceGit ||
			req.DependencyDetailChanges[0].ChangedFields[0] != sdk.DependencyDetailSource {
			t.Fatalf("%s observed mutated request: %#v", phase, req.DependencyDetailChanges)
		}
	}
	mutate := func(req AuditRequest) {
		req.DependencyDetailChanges[0].After.Source = sdk.DependencySourceURL
		req.DependencyDetailChanges[0].ChangedFields[0] = sdk.DependencyDetailRelationship
	}
	registry := newTestRegistry()
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "mutating", SupportedEcosystems: []Ecosystem{EcosystemNPM}},
		onReady:    mutate,
		onApplicable: func(req AuditRequest) {
			assertOriginal("mutating auditor Applicable", req)
			mutate(req)
		},
		run: func(req AuditRequest) AuditResult {
			assertOriginal("mutating auditor Audit", req)
			mutate(req)
			return AuditResult{}
		},
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "observing", SupportedEcosystems: []Ecosystem{EcosystemNPM}},
		onReady: func(req AuditRequest) {
			assertOriginal("observing auditor Ready", req)
		},
		onApplicable: func(req AuditRequest) {
			assertOriginal("observing auditor Applicable", req)
		},
		run: func(req AuditRequest) AuditResult {
			assertOriginal("observing auditor Audit", req)
			return AuditResult{}
		},
	})

	if _, err := NewEngine(registry).Audit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	assertOriginal("caller", request)
}

func TestEngineAudit_SkipsNotReadyOrNotApplicableAuditors(t *testing.T) {
	registry := newTestRegistry()
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "not-ready", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		ready:      new(false),
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "not-applicable", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		applicable: new(false),
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "usable", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     AuditResult{Findings: []Finding{{ID: "1"}}},
	})

	engine := NewEngine(registry)
	result, err := engine.Audit(context.Background(), AuditRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM})
	if err == nil {
		t.Fatal("expected joined error for skipped auditors")
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "1" {
		t.Fatalf("expected applicable ready auditor result, got %#v", result.Findings)
	}
}
