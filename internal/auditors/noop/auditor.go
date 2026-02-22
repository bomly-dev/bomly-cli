package noop

import (
	"context"

	"github.com/bomly/bomly-cli/internal/scan"
)

// Auditor is a baseline auditor that returns no findings.
type Auditor struct {
	Ecosystem scan.Ecosystem
	Priority  int
}

// Descriptor describes the no-op auditor.
func (a Auditor) Descriptor() scan.AuditorDescriptor {
	return scan.AuditorDescriptor{
		Name:                "noop-" + string(a.Ecosystem) + "-auditor",
		ImplementationType:  scan.NativeDetector,
		SupportedEcosystems: []scan.Ecosystem{a.Ecosystem},
		SupportedModes:      []scan.TargetMode{scan.TargetModeFullGraph, scan.TargetModeComponent},
		Priority:            a.Priority,
		Required:            false,
	}
}

// Audit returns an empty audit result.
func (a Auditor) Audit(_ context.Context, req scan.AuditRequest) (scan.AuditResult, error) {
	return scan.AuditResult{
		Graph:      req.Graph,
		Target:     req.Target,
		Findings:   nil,
		RiskScores: nil,
	}, nil
}
