package noop

import (
	"context"
	"testing"

	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/scan"
)

func TestAuditorDescriptorAndAudit(t *testing.T) {
	auditor := Auditor{Ecosystem: scan.EcosystemNPM, Priority: 42}
	descriptor := auditor.Descriptor()
	if descriptor.Name != "noop-npm-auditor" {
		t.Fatalf("unexpected descriptor name %q", descriptor.Name)
	}
	if descriptor.Priority != 42 {
		t.Fatalf("unexpected priority %d", descriptor.Priority)
	}

	req := scan.AuditRequest{
		Graph:  model.New(),
		Target: model.NewPackageRef("app", "1.0.0"),
	}
	result, err := auditor.Audit(context.Background(), req)
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if result.Graph != req.Graph || result.Target != req.Target {
		t.Fatalf("expected graph/target passthrough, got %#v", result)
	}
	if len(result.Findings) != 0 || len(result.RiskScores) != 0 {
		t.Fatalf("expected no findings or risk scores, got %#v", result)
	}
}
