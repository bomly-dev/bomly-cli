package output

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk"
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

// Without a registry the package reference is still a package URL, and a
// package URL already says what the package is called. The fallback reads it
// rather than printing it: a findings table whose Package column says
// "pkg:npm/%40scope/deep@2.0.0" where the enriched rows say "@scope/deep" is
// showing the reader a lookup key.
func TestFindingsFromScanWithoutRegistryIdentifiesFromThePurl(t *testing.T) {
	findings := FindingsFromScan([]sdk.Finding{{
		ID:         "GHSA-x",
		Kind:       sdk.FindingKindVulnerability,
		PackageRef: "pkg:npm/%40scope/deep@2.0.0",
	}}, nil)
	got := findings[0].Package
	want := FindingPackageRef{
		Name:      "@scope/deep",
		Org:       "scope",
		Version:   "2.0.0",
		Purl:      "pkg:npm/%40scope/deep@2.0.0",
		Ecosystem: "npm",
	}
	if got != want {
		t.Fatalf("purl fallback identity: got %#v, want %#v", got, want)
	}
}

// A reference that is not a package URL has nothing better behind it, so the
// raw string stays the name. This is the case the fallback must not lose.
func TestFindingsFromScanKeepsANonPurlReferenceVerbatim(t *testing.T) {
	findings := FindingsFromScan([]sdk.Finding{{
		ID:         "POLICY-1",
		Kind:       sdk.FindingKindPackage,
		PackageRef: "not-a-purl",
	}}, nil)
	got := findings[0].Package
	if got.Name != "not-a-purl" || got.Purl != "not-a-purl" || got.Version != "" || got.Ecosystem != "" {
		t.Fatalf("non-purl reference should survive verbatim, got %#v", got)
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
	pkg, ok := registry.Get("pkg:npm/@tailwindcss/postcss@4.0.0")
	if !ok {
		t.Fatal("scoped package missing from fixture")
	}
	pkg.Remediation = &sdk.PackageRemediation{
		Status:             sdk.PackageRemediationComplete,
		RecommendedVersion: "4.0.1",
	}
	packages := PackagesFromRegistry(registry)
	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].Name != "@tailwindcss/postcss" || packages[0].Org != "tailwindcss" {
		t.Fatalf("scoped identity mangled: got name=%q org=%q", packages[0].Name, packages[0].Org)
	}
	if packages[0].Remediation == nil ||
		packages[0].Remediation.Status != sdk.PackageRemediationComplete ||
		packages[0].Remediation.RecommendedVersion != "4.0.1" {
		t.Fatalf("remediation projection missing: %#v", packages[0].Remediation)
	}
	packages[0].Remediation.RecommendedVersion = "9.0.0"
	if pkg.Remediation.RecommendedVersion != "4.0.1" {
		t.Fatalf("package projection mutated registry remediation: %#v", pkg.Remediation)
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
