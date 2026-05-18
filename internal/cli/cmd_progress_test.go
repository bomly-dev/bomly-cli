package cli

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	diffengine "github.com/bomly-dev/bomly-cli/internal/engine/diff"
	"github.com/bomly-dev/bomly-cli/internal/progress"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestMatchProgressChildren_ReportsMatcherCounts(t *testing.T) {
	g := sdk.New()
	for _, pkg := range []*sdk.Package{
		sdk.NewPackage(sdk.Package{
			Name:    "react",
			Version: "18.2.0",
			Licenses: []sdk.PackageLicense{{
				Type:  "deps.dev",
				Value: "MIT",
			}},
			Vulnerabilities: []sdk.PackageVulnerability{
				{ID: "OSV-1", Source: "osv"},
				{ID: "CVE-1", Source: "grype"},
			},
		}),
		sdk.NewPackage(sdk.Package{
			Name:    "zod",
			Version: "3.23.0",
			Licenses: []sdk.PackageLicense{{
				Type:  "ClearlyDefined",
				Value: "Apache-2.0",
			}},
			Vulnerabilities: []sdk.PackageVulnerability{
				{ID: "OSV-2", Source: "osv"},
			},
		}),
	} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("AddPackage() error = %v", err)
		}
	}

	children := matchProgressChildren(g, []string{
		opts.DepsdevCheckerName,
		opts.ClearlyDefinedCheckerName,
		opts.OSVMatcherName,
		opts.GrypeMatcherName,
	}, nil)

	details := make(map[string]string, len(children))
	for _, child := range children {
		details[child.Label] = child.Detail
	}
	if details["deps.dev"] != "[1 matched packages]" {
		t.Fatalf("expected deps.dev package count, got %#v", children)
	}
	if details["ClearlyDefined"] != "[1 matched packages]" {
		t.Fatalf("expected ClearlyDefined package count, got %#v", children)
	}
	if details["OSV"] != "[2 matched packages, 2 vulnerabilities]" {
		t.Fatalf("expected OSV matcher counts, got %#v", children)
	}
	if details["Grype"] != "[1 matched packages, 1 vulnerabilities]" {
		t.Fatalf("expected Grype matcher counts, got %#v", children)
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
			{Disposition: sdk.FindingDispositionFail},
			{Disposition: sdk.FindingDispositionWarn},
		},
	})
	if child.Icon != progress.CrossMark {
		t.Fatalf("expected failing outcome icon, got %#v", child)
	}
	if child.Detail != "[1 introduced failing, 1 warnings]" {
		t.Fatalf("unexpected policy outcome detail: %#v", child)
	}
}
