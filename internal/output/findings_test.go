package output

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func scopedNPMRegistry(t *testing.T) *sdk.PackageRegistry {
	t.Helper()
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{
			PURL:      "pkg:npm/@tailwindcss/postcss@4.0.0",
			Ecosystem: sdk.EcosystemNPM,
			Org:       "tailwindcss",
			Name:      "postcss",
			Version:   "4.0.0",
		},
		Vulnerabilities: []sdk.Vulnerability{{
			ID:             "GHSA-scoped",
			Aliases:        []string{"CVE-2026-0001"},
			Source:         "osv",
			ParsedSeverity: sdk.SeverityHigh,
			FixedIn:        "4.0.1",
		}},
	})
	return registry
}

func TestFindingsFromScanPreservesScopedIdentity(t *testing.T) {
	registry := scopedNPMRegistry(t)
	findings := FindingsFromScan([]sdk.Finding{{
		ID:              "GHSA-scoped",
		Kind:            sdk.FindingKindVulnerability,
		PackageRef:      "pkg:npm/@tailwindcss/postcss@4.0.0",
		VulnerabilityID: "GHSA-scoped",
		DependencyRefs:  []string{"tailwindcss:postcss@4.0.0"},
		Source:          "osv",
	}}, registry)

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Package.Name != "@tailwindcss/postcss" {
		t.Fatalf("scoped name collapsed: got %q, want %q", f.Package.Name, "@tailwindcss/postcss")
	}
	if f.Package.Org != "tailwindcss" {
		t.Fatalf("org missing: got %q", f.Package.Org)
	}
	if f.Package.Purl != "pkg:npm/@tailwindcss/postcss@4.0.0" {
		t.Fatalf("purl missing: got %q", f.Package.Purl)
	}
	if f.VulnerabilityID != "GHSA-scoped" {
		t.Fatalf("vulnerability_id not carried: got %q", f.VulnerabilityID)
	}
	if len(f.DependencyRefs) != 1 || f.DependencyRefs[0] != "tailwindcss:postcss@4.0.0" {
		t.Fatalf("dependency_refs not carried: got %#v", f.DependencyRefs)
	}
	// Severity backfilled from the referenced advisory when the finding
	// itself carries none.
	if f.Severity != sdk.SeverityHigh {
		t.Fatalf("severity not backfilled from advisory: got %q", f.Severity)
	}
	if got := f.Package.DisplayLabel(); got != "@tailwindcss/postcss@4.0.0" {
		t.Fatalf("display label mismatch: got %q", got)
	}
}

func TestFindingsFromScanWithoutRegistryFallsBackToPurl(t *testing.T) {
	findings := FindingsFromScan([]sdk.Finding{{
		ID:         "GHSA-x",
		Kind:       sdk.FindingKindVulnerability,
		PackageRef: "pkg:npm/lib@1.0.0",
	}}, nil)
	if findings[0].Package.Purl != "pkg:npm/lib@1.0.0" || findings[0].Package.Name != "pkg:npm/lib@1.0.0" {
		t.Fatalf("expected purl fallback identity, got %#v", findings[0].Package)
	}
}

func TestFindingVulnerabilityInPackagesJoinsByPurlAndAlias(t *testing.T) {
	registry := scopedNPMRegistry(t)
	packages := PackagesFromRegistry(registry)
	finding := AuditFinding{
		ID:              "CVE-2026-0001",
		Kind:            sdk.FindingKindVulnerability,
		VulnerabilityID: "CVE-2026-0001", // alias of GHSA-scoped
		Package:         FindingPackageRef{Purl: "pkg:npm/@tailwindcss/postcss@4.0.0"},
	}
	vuln := FindingVulnerabilityInPackages(finding, packages)
	if vuln == nil || vuln.ID != "GHSA-scoped" {
		t.Fatalf("alias join failed: got %#v", vuln)
	}
	if vuln.FixedIn != "4.0.1" {
		t.Fatalf("advisory detail missing on joined ref: got %#v", vuln)
	}

	if got := FindingVulnerabilityInPackages(AuditFinding{Package: FindingPackageRef{Purl: "pkg:npm/other@1.0.0"}, VulnerabilityID: "GHSA-scoped"}, packages); got != nil {
		t.Fatalf("expected nil for unknown package, got %#v", got)
	}
	if got := FindingVulnerabilityInPackages(AuditFinding{}, packages); got != nil {
		t.Fatalf("expected nil for empty purl, got %#v", got)
	}
}

func TestPackagesFromRegistryUsesEcosystemNativeNames(t *testing.T) {
	registry := scopedNPMRegistry(t)
	packages := PackagesFromRegistry(registry)
	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].Name != "@tailwindcss/postcss" || packages[0].Org != "tailwindcss" {
		t.Fatalf("scoped identity mangled: got name=%q org=%q", packages[0].Name, packages[0].Org)
	}
}

func TestPackagesFromRegistriesPrefersHeadAndKeepsBaseOnly(t *testing.T) {
	base := sdk.NewPackageRegistry()
	base.Add(&sdk.Package{
		Coordinates:     sdk.Coordinates{PURL: "pkg:npm/shared@1.0.0", Name: "shared", Version: "1.0.0"},
		Vulnerabilities: []sdk.Vulnerability{{ID: "GHSA-base-view", Source: "osv"}},
	})
	base.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: "pkg:npm/base-only@1.0.0", Name: "base-only", Version: "1.0.0"},
	})
	head := sdk.NewPackageRegistry()
	head.Add(&sdk.Package{
		Coordinates:     sdk.Coordinates{PURL: "pkg:npm/shared@1.0.0", Name: "shared", Version: "1.0.0"},
		Vulnerabilities: []sdk.Vulnerability{{ID: "GHSA-head-view", Source: "osv"}},
	})

	merged := PackagesFromRegistries(base, head)
	if len(merged) != 2 {
		t.Fatalf("expected two packages, got %d", len(merged))
	}
	byPurl := map[string]ScanPackageEntry{}
	for _, entry := range merged {
		byPurl[entry.Purl] = entry
	}
	shared, ok := byPurl["pkg:npm/shared@1.0.0"]
	if !ok || len(shared.Vulnerabilities) != 1 || shared.Vulnerabilities[0].ID != "GHSA-head-view" {
		t.Fatalf("head entry should win for shared purl, got %#v", shared)
	}
	if _, ok := byPurl["pkg:npm/base-only@1.0.0"]; !ok {
		t.Fatal("base-only package missing from union")
	}
}
