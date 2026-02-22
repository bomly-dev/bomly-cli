package cli

import (
	"testing"

	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/scan"
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

	children := licenseProgressChildren([]scan.ResolveGraphResult{{
		Graphs: scan.SingleGraphContainer(g, scan.ManifestMetadata{Path: "package.json", Kind: "npm"}),
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
