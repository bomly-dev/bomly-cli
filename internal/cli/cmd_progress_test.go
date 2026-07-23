package cli

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	diffengine "github.com/bomly-dev/bomly-cli/internal/engine/diff"
	"github.com/bomly-dev/bomly-cli/internal/progress"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestMatchProgressChildren_ReportsMatcherCounts(t *testing.T) {
	children := matchProgressChildren([]sdk.MatcherStats{
		{Name: "license-matcher", DisplayName: "Example License Matcher", MatchedPackages: 2, Licenses: 3},
		{Name: "vulnerability-matcher", DisplayName: "Example Vulnerability Matcher", MatchedPackages: 3, UnmatchedPackages: 1, Vulnerabilities: 4},
	}, nil)

	details := make(map[string]string, len(children))
	for _, child := range children {
		details[child.Label] = child.Detail
	}
	if details["Example License Matcher"] != "[2 matched packages, 3 licenses]" {
		t.Fatalf("expected license matcher package count, got %#v", children)
	}
	if details["Example Vulnerability Matcher"] != "[3 matched packages, 1 unmatched packages, 4 vulnerabilities]" {
		t.Fatalf("expected vulnerability matcher counts, got %#v", children)
	}
}

func TestAuditProgressChildren_UsesAuditorRunsNotFindingSources(t *testing.T) {
	children := auditProgressChildren(
		[]string{opts.VulnerabilityAuditorName},
		map[string]int{opts.VulnerabilityAuditorName: 3},
		nil,
	)

	if len(children) != 1 {
		t.Fatalf("expected 1 child, got %#v", children)
	}
	if children[0].Label != "Vulnerability Auditor" {
		t.Fatalf("unexpected auditor label: %#v", children[0])
	}
	if children[0].Detail != "[3 findings]" {
		t.Fatalf("unexpected auditor detail: %#v", children[0])
	}
}

func TestAuditProgressChildren_DoesNotRepeatAuditorSuffix(t *testing.T) {
	children := auditProgressChildren(
		[]string{"Meme Dependency Auditor"},
		map[string]int{"Meme Dependency Auditor": 0},
		nil,
	)

	if len(children) != 1 {
		t.Fatalf("expected 1 child, got %#v", children)
	}
	if children[0].Label != "Meme Dependency Auditor" {
		t.Fatalf("unexpected auditor label: %#v", children[0])
	}
}

func TestSubprojectProgressChildren_UsesGitIdentityWhenConcreteTargetIsFilesystem(t *testing.T) {
	children := subprojectProgressChildren([]sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget: sdk.ExecutionTarget{
				Kind:          sdk.ExecutionTargetFilesystem,
				Location:      `C:\Temp\bomly-git-ref-123`,
				RepositoryURL: "https://github.com/bomly-dev/bomly-cli",
				Ref:           "main",
			},
			RelativePath: ".",
			Ecosystem:    sdk.EcosystemNPM,
		},
	}})

	if len(children) != 1 {
		t.Fatalf("expected 1 child, got %#v", children)
	}
	if children[0].Label != "https://github.com/bomly-dev/bomly-cli @ main (npm)" {
		t.Fatalf("unexpected target label: %#v", children[0])
	}
}

func TestDiffPolicyOutcomeProgressChild_ReportsIntroducedOutcome(t *testing.T) {
	child := diffPolicyOutcomeProgressChild(&diffengine.Audit{
		Introduced: []sdk.Finding{
			{PolicyStatus: sdk.FindingPolicyStatusFail},
			{PolicyStatus: sdk.FindingPolicyStatusWarn},
		},
	})
	if child.Icon != progress.CrossMark {
		t.Fatalf("expected failing outcome icon, got %#v", child)
	}
	if child.Detail != "[1 failing, 1 warnings]" {
		t.Fatalf("unexpected policy outcome detail: %#v", child)
	}
}

func TestDiffPolicyOutcomeProgressChild_PersistedFindingsAlsoFail(t *testing.T) {
	// A persisted finding is tied to a package the diff actually changed, so
	// it must gate the run exactly like an introduced one.
	child := diffPolicyOutcomeProgressChild(&diffengine.Audit{
		Persisted: []sdk.Finding{
			{PolicyStatus: sdk.FindingPolicyStatusFail},
		},
	})
	if child.Icon != progress.CrossMark {
		t.Fatalf("expected failing outcome icon for a persisted failing finding, got %#v", child)
	}
	if child.Detail != "[1 failing, 0 warnings]" {
		t.Fatalf("unexpected policy outcome detail: %#v", child)
	}
}
