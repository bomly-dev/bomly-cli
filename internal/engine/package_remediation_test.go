package engine

import (
	"context"
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDerivePackageRemediation(t *testing.T) {
	tests := []struct {
		name            string
		vulnerabilities []sdk.Vulnerability
		want            *sdk.PackageRemediation
	}{
		{
			name: "no vulnerabilities",
		},
		{
			name: "one fixed in version",
			vulnerabilities: []sdk.Vulnerability{{
				ID:       "VULN-1",
				FixState: sdk.FixStateFixed,
				FixedIn:  "1.2.0",
			}},
			want: &sdk.PackageRemediation{
				Status:             sdk.PackageRemediationComplete,
				RecommendedVersion: "1.2.0",
			},
		},
		{
			name: "uses preferred source and highest required version",
			vulnerabilities: []sdk.Vulnerability{
				{
					ID:            "VULN-1",
					FixedIn:       "1.4.0",
					FixAvailable:  []sdk.FixAvailable{{Version: "9.0.0"}},
					FixedVersions: []string{"8.0.0"},
				},
				{
					ID: "VULN-2",
					FixAvailable: []sdk.FixAvailable{
						{Version: "2.1.0"},
						{Version: "2.0.0"},
					},
					FixedVersions: []string{"7.0.0"},
				},
				{
					ID:            "VULN-3",
					FixedVersions: []string{"1.5.0", "1.6.0"},
				},
			},
			want: &sdk.PackageRemediation{
				Status:             sdk.PackageRemediationComplete,
				RecommendedVersion: "2.0.0",
			},
		},
		{
			name: "mixed fix and missing evidence",
			vulnerabilities: []sdk.Vulnerability{
				{ID: "VULN-1", FixedIn: "1.2.0"},
				{ID: "VULN-2"},
			},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name: "mixed fix and unavailable",
			vulnerabilities: []sdk.Vulnerability{
				{ID: "VULN-1", FixedIn: "1.2.0"},
				{ID: "VULN-2", FixState: sdk.FixStateNotFixed},
			},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name: "all unavailable",
			vulnerabilities: []sdk.Vulnerability{
				{ID: "VULN-1", FixState: sdk.FixStateNotFixed},
				{ID: "VULN-2", FixState: sdk.FixStateWontFix},
			},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationUnavailable},
		},
		{
			name: "unknown evidence",
			vulnerabilities: []sdk.Vulnerability{
				{ID: "VULN-1"},
				{ID: "VULN-2", FixState: sdk.FixStateNotFixed},
			},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationUnknown},
		},
		{
			name: "contradictory evidence",
			vulnerabilities: []sdk.Vulnerability{{
				ID:       "VULN-1",
				FixState: sdk.FixStateWontFix,
				FixedIn:  "1.2.0",
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationUnknown},
		},
		{
			name: "incomparable versions across vulnerabilities",
			vulnerabilities: []sdk.Vulnerability{
				{ID: "VULN-1", FixedIn: "release-a"},
				{ID: "VULN-2", FixedIn: "release-b"},
			},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
		{
			name: "incomparable versions within one source",
			vulnerabilities: []sdk.Vulnerability{{
				ID:            "VULN-1",
				FixedVersions: []string{"release-a", "release-b"},
			}},
			want: &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := derivePackageRemediation(tt.vulnerabilities)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("derivePackageRemediation() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestDerivePackageRemediationsOverwritesAndIsIdempotent(t *testing.T) {
	registry := sdk.NewPackageRegistry()
	pkg := registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: "pkg:npm/example@1.0.0"},
		Vulnerabilities: []sdk.Vulnerability{{
			ID:      "VULN-1",
			FixedIn: "1.2.0",
		}},
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "99.0.0",
		},
	})

	derivePackageRemediations(registry)
	first := pkg.Remediation.Clone()
	derivePackageRemediations(registry)
	if !reflect.DeepEqual(pkg.Remediation, first) {
		t.Fatalf("second derivation changed result: first %#v, second %#v", first, pkg.Remediation)
	}
	if pkg.Remediation.RecommendedVersion != "1.2.0" {
		t.Fatalf("incoming remediation remained authoritative: %#v", pkg.Remediation)
	}
}

func TestDerivePackageRemediationIsOrderIndependent(t *testing.T) {
	first := []sdk.Vulnerability{
		{ID: "VULN-1", FixedIn: "1.2.0"},
		{ID: "VULN-2", FixedIn: "2.0.0"},
	}
	second := []sdk.Vulnerability{first[1], first[0]}

	if !reflect.DeepEqual(derivePackageRemediation(first), derivePackageRemediation(second)) {
		t.Fatalf("derivation changed with matcher order: %#v != %#v",
			derivePackageRemediation(first), derivePackageRemediation(second))
	}
}

func TestEngineMatchDerivesRemediationAfterMatcherConsolidation(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	matchers := []fakeMatcher{
		{
			name: "advisory-a",
			run: func(registry *sdk.PackageRegistry) {
				registry.Ensure(purl).Vulnerabilities = append(
					registry.Ensure(purl).Vulnerabilities,
					sdk.Vulnerability{
						ID:      "GHSA-example",
						Aliases: []string{"CVE-2026-0001"},
						FixedIn: "1.2.0",
						Source:  "source-a",
					},
				)
			},
		},
		{
			name: "advisory-b",
			run: func(registry *sdk.PackageRegistry) {
				registry.Ensure(purl).Vulnerabilities = append(
					registry.Ensure(purl).Vulnerabilities,
					sdk.Vulnerability{
						ID:            "CVE-2026-0001",
						FixedVersions: []string{"1.2.0", "1.3.0"},
						Source:        "source-b",
					},
				)
			},
		},
	}

	run := func(t *testing.T, ordered []fakeMatcher) *sdk.Package {
		t.Helper()
		components := newTestRegistry()
		for _, matcher := range ordered {
			components.registerMatcher(matcher)
		}
		result, err := NewEngine(components).Match(context.Background(), sdk.MatchRequest{
			Graph:    sdk.New(),
			Registry: sdk.NewPackageRegistry(),
		})
		if err != nil {
			t.Fatalf("Match() error = %v", err)
		}
		pkg, ok := result.Registry.Get(purl)
		if !ok {
			t.Fatalf("Match() omitted package %q", purl)
		}
		return pkg.Clone()
	}

	forward := run(t, matchers)
	reverse := run(t, []fakeMatcher{matchers[1], matchers[0]})
	if !reflect.DeepEqual(forward.Remediation, reverse.Remediation) {
		t.Fatalf("matcher order changed remediation: forward %#v, reverse %#v",
			forward.Remediation, reverse.Remediation)
	}
	if len(forward.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities were not consolidated before derivation: %#v", forward.Vulnerabilities)
	}
	want := &sdk.PackageRemediation{
		Status:             sdk.PackageRemediationComplete,
		RecommendedVersion: "1.2.0",
	}
	if !reflect.DeepEqual(forward.Remediation, want) {
		t.Fatalf("remediation = %#v, want %#v", forward.Remediation, want)
	}
}

func TestEngineMatchDerivesRemediationWhenTargetIsNotMatchEligible(t *testing.T) {
	const purl = "pkg:npm/local-workspace@1.0.0"
	dependency := sdk.NewDependency(sdk.Dependency{
		Coordinates: sdk.Coordinates{
			PURL:    purl,
			Name:    "local-workspace",
			Version: "1.0.0",
			Type:    sdk.PackageTypeApplication,
		},
		Source: sdk.DependencySourceWorkspace,
	})
	graph := sdk.New()
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: dependency.Coordinates,
		Vulnerabilities: []sdk.Vulnerability{{
			ID:      "VULN-LOCAL",
			FixedIn: "1.1.0",
		}},
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "99.0.0",
		},
	})
	matcher := &eligibilityCapturingMatcher{}
	components := newTestRegistry()
	components.registerMatcher(matcher)

	result, err := NewEngine(components).Match(context.Background(), sdk.MatchRequest{
		Graph:    graph,
		Registry: registry,
		Target:   dependency,
	})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if matcher.calls != 0 {
		t.Fatalf("ineligible target invoked matcher %d times", matcher.calls)
	}
	pkg, ok := result.Registry.Get(purl)
	if !ok || pkg.Remediation == nil || pkg.Remediation.RecommendedVersion != "1.1.0" {
		t.Fatalf("central derivation did not replace incoming remediation: %#v", pkg)
	}
}
