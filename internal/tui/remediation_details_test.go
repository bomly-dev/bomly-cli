package tui

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-sdk"
)

func TestComponentDetailsShowPackageRemediation(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: purl, Name: "example", Version: "1.0.0"},
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
			Suggestions: []sdk.PackageRemediationSuggestion{{
				AffectedDependencyRefs: []string{"example@1.0.0"},
				ManifestPath:           "package-lock.json",
				Action:                 sdk.RemediationActionDirectBump,
			}},
		},
	})

	lines := componentDetails(nil, registry, listPackageRow{
		id:          "example@1.0.0",
		displayName: "example",
		version:     "1.0.0",
		purl:        " " + purl + " ",
	}, listPackageRow{displayName: "package-lock.json"})
	plain := render.StripANSI(strings.Join(lines, "\n"))
	for _, want := range []string{
		"Remediation Suggestion",
		"Fix status: Complete fix available",
		"Recommended version: 1.2.0",
		"Suggested action: Direct bump",
		"Manifest: package-lock.json",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("component details missing %q:\n%s", want, plain)
		}
	}
	vulnerabilitiesIndex := strings.Index(plain, "Vulnerabilities")
	remediationIndex := strings.Index(plain, "Remediation Suggestion\n")
	licensesIndex := strings.Index(plain, "Licenses")
	if vulnerabilitiesIndex < 0 || remediationIndex <= vulnerabilitiesIndex ||
		licensesIndex <= remediationIndex {
		t.Fatalf("remediation section must follow vulnerabilities and precede licenses:\n%s", plain)
	}
	assertOneBlankBeforeSection(t, lines, "Remediation Suggestion")
	assertOneBlankBeforeSection(t, lines, "Licenses (0)")
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
	if !strings.Contains(plain, "Fix status: No fix available") {
		t.Fatalf("diff component details omitted remediation:\n%s", plain)
	}
	if strings.Contains(plain, "Recommended version:") {
		t.Fatalf("unavailable remediation displayed a recommendation:\n%s", plain)
	}
	if vulnerabilitiesIndex, remediationIndex := strings.Index(plain, "Vulnerabilities"), strings.Index(plain, "Remediation Suggestion\n"); vulnerabilitiesIndex < 0 || remediationIndex <= vulnerabilitiesIndex {
		t.Fatalf("diff remediation section must follow vulnerabilities:\n%s", plain)
	}
	assertOneBlankBeforeSection(t, lines, "Remediation Suggestion")
}

func assertOneBlankBeforeSection(t *testing.T, lines []string, section string) {
	t.Helper()
	plain := make([]string, len(lines))
	for idx, line := range lines {
		plain[idx] = render.StripANSI(line)
	}
	for idx, line := range plain {
		if line != section {
			continue
		}
		if idx < 2 || plain[idx-1] != "" || plain[idx-2] == "" {
			t.Fatalf("%s must have exactly one blank line before it:\n%s", section, strings.Join(plain, "\n"))
		}
		return
	}
	t.Fatalf("section %q not found:\n%s", section, strings.Join(plain, "\n"))
}

func TestCollectComponentChangesUsesRegistryForEachSide(t *testing.T) {
	const (
		addedPURL   = "pkg:npm/added@1.0.0"
		changedPURL = "pkg:npm/changed@2.0.0"
		removedPURL = "pkg:npm/removed@1.0.0"
	)
	baseRegistry := sdk.NewPackageRegistry()
	headRegistry := sdk.NewPackageRegistry()
	addRemediationPackage := func(
		registry *sdk.PackageRegistry,
		purl string,
		status sdk.PackageRemediationStatus,
		version string,
	) {
		registry.Add(&sdk.Package{
			Coordinates: sdk.Coordinates{PURL: purl},
			Remediation: &sdk.PackageRemediation{
				Status:             status,
				RecommendedVersion: version,
			},
		})
	}
	addRemediationPackage(headRegistry, addedPURL, sdk.PackageRemediationComplete, "1.1.0")
	addRemediationPackage(baseRegistry, addedPURL, sdk.PackageRemediationUnavailable, "")
	addRemediationPackage(headRegistry, changedPURL, sdk.PackageRemediationPartial, "")
	addRemediationPackage(baseRegistry, changedPURL, sdk.PackageRemediationComplete, "9.0.0")
	addRemediationPackage(baseRegistry, removedPURL, sdk.PackageRemediationUnavailable, "")
	addRemediationPackage(headRegistry, removedPURL, sdk.PackageRemediationComplete, "9.0.0")

	model := &DiffModel{
		payload: output.DiffResponse{Results: output.DiffResults{
			Manifests: []output.DiffManifestResult{{
				Added: []output.DiffPackageChange{{
					Package: output.PackageRef{Purl: addedPURL},
				}},
				Changed: []output.DiffChangedPackage{{
					Before: output.PackageRef{Purl: "pkg:npm/changed@1.0.0"},
					After:  output.PackageRef{Purl: changedPURL},
				}},
				Removed: []output.DiffPackageChange{{
					Package: output.PackageRef{Purl: removedPURL},
				}},
			}},
		}},
		baseRegistry: baseRegistry,
		headRegistry: headRegistry,
	}

	changes := model.collectComponentChanges()
	if len(changes) != 3 {
		t.Fatalf("component changes = %#v, want added, changed, and removed", changes)
	}
	byStatus := make(map[string]*sdk.PackageRemediation, len(changes))
	for _, change := range changes {
		byStatus[change.status] = change.remediation
	}
	if got := byStatus["added"]; got == nil ||
		got.Status != sdk.PackageRemediationComplete || got.RecommendedVersion != "1.1.0" {
		t.Fatalf("added remediation = %#v, want head complete 1.1.0", got)
	}
	if got := byStatus["changed"]; got == nil || got.Status != sdk.PackageRemediationPartial {
		t.Fatalf("changed remediation = %#v, want head partial", got)
	}
	if got := byStatus["removed"]; got == nil || got.Status != sdk.PackageRemediationUnavailable {
		t.Fatalf("removed remediation = %#v, want base unavailable", got)
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
