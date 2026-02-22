package cli

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/scan"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestLicenseProgressChildren_CountsPackagesWithLicensesPerSource(t *testing.T) {
	g := model.New()
	for _, pkg := range []*model.Package{
		model.NewPackage(model.Package{
			Name:    "react",
			Version: "18.2.0",
			Licenses: []model.PackageLicense{{
				Type:  "external-depsdev",
				Value: "MIT",
			}},
		}),
		model.NewPackage(model.Package{
			Name:    "zod",
			Version: "3.23.0",
			Licenses: []model.PackageLicense{{
				Type:  "external-depsdev",
				Value: "MIT",
			}},
		}),
		model.NewPackage(model.Package{
			Name:    "chalk",
			Version: "5.4.1",
			Licenses: []model.PackageLicense{{
				Type:  "external-clearlydefined",
				Value: "ISC",
			}},
		}),
	} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("AddPackage() error = %v", err)
		}
	}

	children := licenseProgressChildren([]model.DetectionResult{{
		Graphs: scan.SingleGraphContainer(g, model.ManifestMetadata{Path: "package.json", Kind: "npm"}),
	}})

	if len(children) != 2 {
		t.Fatalf("expected 2 children, got %#v", children)
	}
	counts := make(map[string]string, len(children))
	for _, child := range children {
		counts[child.Label] = child.Detail
	}
	if counts["deps.dev"] != "[2 licenses]" {
		t.Fatalf("expected deps.dev count based on packages, got %#v", children)
	}
	if counts["ClearlyDefined"] != "[1 licenses]" {
		t.Fatalf("expected ClearlyDefined count based on packages, got %#v", children)
	}
}

func TestMatchProgressChildren_ReportsMatcherCounts(t *testing.T) {
	g := model.New()
	for _, pkg := range []*model.Package{
		model.NewPackage(model.Package{
			Name:    "react",
			Version: "18.2.0",
			Licenses: []model.PackageLicense{{
				Type:  "external-depsdev",
				Value: "MIT",
			}},
			Vulnerabilities: []model.PackageVulnerability{
				{ID: "OSV-1", Source: "osv"},
				{ID: "CVE-1", Source: "grype"},
			},
		}),
		model.NewPackage(model.Package{
			Name:    "zod",
			Version: "3.23.0",
			Licenses: []model.PackageLicense{{
				Type:  "external-clearlydefined",
				Value: "Apache-2.0",
			}},
			Vulnerabilities: []model.PackageVulnerability{
				{ID: "OSV-2", Source: "osv"},
			},
		}),
	} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("AddPackage() error = %v", err)
		}
	}

	children := matchProgressChildren(g, []string{
		depsdevCheckerName,
		clearlyDefinedCheckerName,
		osvMatcherName,
		grypeMatcherName,
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
		[]string{severityPolicyAuditorName},
		map[string]int{severityPolicyAuditorName: 3},
		nil,
	)

	if len(children) != 1 {
		t.Fatalf("expected 1 child, got %#v", children)
	}
	if children[0].Label != "Severity Policy Auditor" {
		t.Fatalf("unexpected auditor label: %#v", children[0])
	}
	if children[0].Detail != "[3 findings]" {
		t.Fatalf("unexpected auditor detail: %#v", children[0])
	}
}
