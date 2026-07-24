package tui

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestComponentDetailsShowPackageRemediation(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: purl, Name: "example", Version: "1.0.0"},
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})

	lines := componentDetails(nil, registry, listPackageRow{
		id:          "example@1.0.0",
		displayName: "example",
		version:     "1.0.0",
		purl:        purl,
	}, listPackageRow{displayName: "package-lock.json"})
	plain := render.StripANSI(strings.Join(lines, "\n"))
	for _, want := range []string{
		"Remediation status: Complete",
		"Recommended version: 1.2.0",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("component details missing %q:\n%s", want, plain)
		}
	}
}

func TestDiffComponentDetailsShowPackageRemediation(t *testing.T) {
	lines := componentChangeDetails(flatComponentChange{
		status:  "added",
		pkgName: "example@1.0.0",
		pkgRef: output.PackageRef{
			Name:    "example",
			Version: "1.0.0",
			Purl:    "pkg:npm/example@1.0.0",
		},
		remediation: &sdk.PackageRemediation{
			Status: sdk.PackageRemediationUnavailable,
		},
	})
	plain := render.StripANSI(strings.Join(lines, "\n"))
	if !strings.Contains(plain, "Remediation status: Unavailable") {
		t.Fatalf("diff component details omitted remediation:\n%s", plain)
	}
	if strings.Contains(plain, "Recommended version:") {
		t.Fatalf("unavailable remediation displayed a recommendation:\n%s", plain)
	}
}

func TestInteractiveModelsHaveNoRemediationTab(t *testing.T) {
	scan := NewScan(output.ProjectDescriptor{}, sdk.ConsolidatedGraph{}, nil, nil)
	diff := NewDiff(output.DiffResponse{}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	for name, tabs := range map[string][]TabSpec{
		"scan": scan.spec.Tabs,
		"diff": diff.spec.Tabs,
	} {
		for _, tab := range tabs {
			if strings.EqualFold(tab.ID, "remediation") || strings.EqualFold(tab.Label, "remediation") {
				t.Fatalf("%s unexpectedly exposes remediation tab: %#v", name, tab)
			}
		}
	}
}
