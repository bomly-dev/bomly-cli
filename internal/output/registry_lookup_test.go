package output_test

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

// lookupRegistry is one enriched package: scoped npm coordinates, an advisory
// stored under its CVE with the GHSA as an alias, and matching-stage licenses.
func lookupRegistry(t *testing.T) *sdk.PackageRegistry {
	t.Helper()
	registry := &sdk.PackageRegistry{}
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{
			PURL:      "pkg:npm/%40scope/deep@2.0.0",
			Ecosystem: sdk.EcosystemNPM,
			Org:       "scope",
			Name:      "deep",
			Version:   "2.0.0",
		},
		Licenses: []sdk.PackageLicense{{Value: "Apache-2.0"}},
		Vulnerabilities: []sdk.Vulnerability{{
			ID:             "CVE-2026-0001",
			Aliases:        []string{"GHSA-deep"},
			ParsedSeverity: sdk.SeverityHigh,
		}},
	})
	return registry
}

func TestRegistryPackageTrimsTheReferenceOnEverySurface(t *testing.T) {
	registry := lookupRegistry(t)
	// The drift this consolidation removes: two of the six copies trimmed and
	// four did not, so a reference with a stray space resolved on the JSON
	// document and vanished in the TUI.
	if pkg := output.RegistryPackage(registry, "  pkg:npm/%40scope/deep@2.0.0 "); pkg == nil {
		t.Fatal("a padded package reference must resolve; the lookup trims")
	}
	if pkg := output.RegistryPackage(registry, "   "); pkg != nil {
		t.Fatalf("a blank reference must not resolve, got %#v", pkg)
	}
	if pkg := output.RegistryPackage(nil, "pkg:npm/%40scope/deep@2.0.0"); pkg != nil {
		t.Fatalf("an unenriched scan has no registry and no package, got %#v", pkg)
	}
}

func TestNodePackageRefIsThePackageNotTheNode(t *testing.T) {
	dep := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "left-pad", Version: "1.3.0",
	}})
	if got := output.NodePackageRef(dep); got != dep.PackageRef {
		t.Fatalf("dependency node key: got %q, want its PackageRef %q", got, dep.PackageRef)
	}

	// Modules and manifests are the project's own artifacts, not consumed
	// packages. Keying them off NodeID() would look up whatever entry happened
	// to share the string.
	module := testnodes.Module("package.json", "app", "1.0.0")
	if got := output.NodePackageRef(module); got != "" {
		t.Fatalf("a module is not a package; got key %q", got)
	}
	if got := output.NodePackageRef(nil); got != "" {
		t.Fatalf("nil node key: got %q, want empty", got)
	}
}

func TestRegistryPackageForNodeResolvesThroughThePackageRef(t *testing.T) {
	registry := lookupRegistry(t)
	dep := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Org: "scope", Name: "deep", Version: "2.0.0",
	}})
	pkg := output.RegistryPackageForNode(registry, dep)
	if pkg == nil {
		t.Fatalf("node %q did not resolve against the registry", dep.PackageRef)
	}
	if pkg.Name != "deep" {
		t.Fatalf("resolved the wrong package: %#v", pkg)
	}
	if got := output.RegistryPackageForNode(registry, testnodes.Module("package.json", "app", "1.0.0")); got != nil {
		t.Fatalf("a module must not resolve to a package, got %#v", got)
	}
}

func TestPackageAdvisoryMatchesAliasesNotJustIDs(t *testing.T) {
	registry := lookupRegistry(t)
	pkg := output.RegistryPackage(registry, "pkg:npm/%40scope/deep@2.0.0")

	if vuln := output.PackageAdvisory(pkg, "CVE-2026-0001"); vuln == nil {
		t.Fatal("advisory not found by its own id")
	}
	// The id a finding names is the id of the source that reported it. An OSV
	// finding names the GHSA while the stored advisory is keyed by its CVE,
	// and an exact-id-only match renders that finding with no severity, no fix
	// version and no KEV flag.
	vuln := output.PackageAdvisory(pkg, "GHSA-deep")
	if vuln == nil {
		t.Fatal("advisory not found by alias")
	}
	if vuln.ID != "CVE-2026-0001" {
		t.Fatalf("alias resolved to the wrong advisory: %#v", vuln)
	}
	if got := output.PackageAdvisory(pkg, "GHSA-unrelated"); got != nil {
		t.Fatalf("unknown id must not resolve, got %#v", got)
	}
	if got := output.PackageAdvisory(pkg, ""); got != nil {
		t.Fatalf("empty id must not resolve, got %#v", got)
	}
}

func TestFindingVulnerabilityIDPrefersTheExplicitField(t *testing.T) {
	// One auditor mints one finding per advisory and lets the ids coincide;
	// another mints several against one advisory and can only say which in
	// VulnerabilityID. The explicit field wins.
	if got := output.FindingVulnerabilityID(sdk.Finding{ID: "policy-1", VulnerabilityID: "CVE-2026-0001"}); got != "CVE-2026-0001" {
		t.Fatalf("explicit vulnerability id ignored: got %q", got)
	}
	if got := output.FindingVulnerabilityID(sdk.Finding{ID: "CVE-2026-0001"}); got != "CVE-2026-0001" {
		t.Fatalf("finding id should stand in when no advisory id is set: got %q", got)
	}
	if got := output.FindingVulnerabilityID(sdk.Finding{}); got != "" {
		t.Fatalf("a finding naming no advisory: got %q, want empty", got)
	}
}

func TestFindingAdvisoryJoinsPackageAndAdvisory(t *testing.T) {
	registry := lookupRegistry(t)
	pkg, vuln := output.FindingAdvisory(registry, sdk.Finding{
		ID:         "GHSA-deep",
		PackageRef: "pkg:npm/%40scope/deep@2.0.0",
	})
	if pkg == nil || vuln == nil {
		t.Fatalf("finding did not join: pkg=%#v vuln=%#v", pkg, vuln)
	}
	if vuln.ID != "CVE-2026-0001" {
		t.Fatalf("joined the wrong advisory: %#v", vuln)
	}

	// A license or policy finding has a package and names no advisory. Both
	// halves are independently optional.
	pkg, vuln = output.FindingAdvisory(registry, sdk.Finding{
		Kind:       sdk.FindingKindLicense,
		PackageRef: "pkg:npm/%40scope/deep@2.0.0",
	})
	if pkg == nil {
		t.Fatal("a license finding still resolves its package")
	}
	if vuln != nil {
		t.Fatalf("a license finding names no advisory, got %#v", vuln)
	}
}

func TestResolvedLicensesPrefersMatchingOverDetection(t *testing.T) {
	registry := lookupRegistry(t)
	coords := sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Org: "scope", Name: "deep", Version: "2.0.0"}

	enriched := testnodes.DepFrom(sdk.DependencyNode{
		Coordinates: coords,
		Licenses:    []sdk.PackageLicense{{Value: "MIT"}},
	})
	got := output.ResolvedLicenses(registry, enriched)
	// Matching's answer is the reconciled one for that PURL; detection's is one
	// producer's reading of one file. Matching wins whole rather than merging.
	if len(got) != 1 || got[0].Value != "Apache-2.0" {
		t.Fatalf("matching licenses should win: got %#v", got)
	}

	unmatched := testnodes.DepFrom(sdk.DependencyNode{
		Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: "unmatched", Version: "1.0.0"},
		Licenses:    []sdk.PackageLicense{{Value: "MIT"}},
	})
	got = output.ResolvedLicenses(registry, unmatched)
	if len(got) != 1 || got[0].Value != "MIT" {
		t.Fatalf("detection licenses should stand in when matching learned none: got %#v", got)
	}
	if got := output.ResolvedLicenses(nil, unmatched); len(got) != 1 || got[0].Value != "MIT" {
		t.Fatalf("an unenriched scan still shows detection licenses: got %#v", got)
	}
}

func TestNodeVulnerabilitiesReadsThroughTheRegistry(t *testing.T) {
	registry := lookupRegistry(t)
	dep := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Org: "scope", Name: "deep", Version: "2.0.0",
	}})
	if got := output.NodeVulnerabilities(registry, dep); len(got) != 1 || got[0].ID != "CVE-2026-0001" {
		t.Fatalf("node advisories: got %#v", got)
	}
	if got := output.NodeVulnerabilities(nil, dep); got != nil {
		t.Fatalf("no registry means no advisories, got %#v", got)
	}
}

func TestIdentifyPackageRefPrefersTheRegistry(t *testing.T) {
	registry := lookupRegistry(t)
	got := output.IdentifyPackageRef(registry, "pkg:npm/%40scope/deep@2.0.0")
	want := output.FindingPackageRef{
		Name:      "@scope/deep",
		Org:       "scope",
		Version:   "2.0.0",
		Purl:      "pkg:npm/%40scope/deep@2.0.0",
		Ecosystem: "npm",
	}
	if got != want {
		t.Fatalf("registry identity: got %#v, want %#v", got, want)
	}
}

func TestIdentifyPackageRefDerivesTheSameIdentityFromThePurlAlone(t *testing.T) {
	// The point of the fallback: an unenriched surface renders the same label
	// the enriched one does, rather than a lookup key. Asserted against the
	// registry answer so the two cannot drift apart.
	registry := lookupRegistry(t)
	const ref = "pkg:npm/%40scope/deep@2.0.0"
	if got, want := output.IdentifyPackageRef(nil, ref), output.IdentifyPackageRef(registry, ref); got != want {
		t.Fatalf("purl-derived identity diverged from the registry answer: got %#v, want %#v", got, want)
	}
}

func TestIdentifyPackageRefSpellsNamesTheWayEachEcosystemDoes(t *testing.T) {
	// Every one of these is the SDK's or purlkit's rule, not this package's:
	// the npm scope marker, the Maven colon, the Go path, PyPI name
	// canonicalization, and the deliberate refusal to guess an ecosystem for
	// pkg:hex (which serves both Elixir and Erlang).
	cases := []struct {
		ref       string
		name      string
		version   string
		ecosystem string
	}{
		{"pkg:npm/%40scope/deep@2.0.0", "@scope/deep", "2.0.0", "npm"},
		{"pkg:npm/left-pad@1.3.0", "left-pad", "1.3.0", "npm"},
		{"pkg:maven/org.apache/commons@1.0", "org.apache:commons", "1.0", "maven"},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "github.com/foo/bar", "v1.2.3", "go"},
		{"pkg:pypi/Flask_Login@2.0", "flask-login", "2.0", "python"},
		{"pkg:hex/plug@1.0", "plug", "1.0", ""},
		{"not-a-purl", "not-a-purl", "", ""},
		{"", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			got := output.IdentifyPackageRef(nil, tc.ref)
			if got.Name != tc.name || got.Version != tc.version || got.Ecosystem != tc.ecosystem {
				t.Fatalf("got %#v, want name=%q version=%q ecosystem=%q", got, tc.name, tc.version, tc.ecosystem)
			}
			if got.Purl != tc.ref {
				t.Fatalf("the reference is the lookup key and must survive: got %q, want %q", got.Purl, tc.ref)
			}
		})
	}
}
