package output

import (
	"slices"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/purlkit"
)

// Every presentation surface -- the JSON and SARIF documents here, the scan and
// diff text renderers, the TUI, and the MCP compact projections -- asks the
// PURL-keyed registry the same handful of questions, and each had grown its own
// answer: thirteen sites spelling out "registry != nil, ref != empty, Get,
// package != nil", four copies of the advisory-by-id-or-alias search, two
// verbatim copies of the registry-licenses-else-detection-licenses rule, and
// four copies of the registry-miss fallback.
//
// They had already drifted. Two of the thirteen trimmed the package reference
// before looking it up and eleven did not, so whether a stray space hid a
// package depended on which surface was asking. Three of the four fallbacks
// printed the raw package URL as the package's name and the fourth printed the
// registry's bare name, which drops an npm scope -- so one unenriched scan
// could call the same package "pkg:npm/%40scope/deep@2.0.0", "@scope/deep" and
// "deep" in three places.
//
// This file is the one home for those rules. Nothing under the presentation
// layers calls PackageRegistry.Get directly any more, and
// TestPresentationLookupsGoThroughTheSharedHelper keeps it that way.

// RegistryPackage returns what the matching stage recorded for a package
// reference, or nil when it recorded nothing.
//
// nil is the normal answer, not an error: a scan without --enrich has an empty
// registry, and every caller here is rendering a detection-time fact that has
// no enrichment behind it.
func RegistryPackage(registry *sdk.PackageRegistry, packageRef string) *sdk.Package {
	packageRef = strings.TrimSpace(packageRef)
	if registry == nil || packageRef == "" {
		return nil
	}
	pkg, ok := registry.Get(packageRef)
	if !ok {
		return nil
	}
	return pkg
}

// NodePackageRef returns the registry key for a graph node: the package it
// resolved to.
//
// The stored truth is DependencyNode.PackageRef, and identity (ADR-0041) makes
// that the node's canonical PURL, so today it equals NodeID(). Asking for the
// package reference rather than the node id says what the lookup means, and
// leaves the two free to diverge -- a graph carrying several occurrence nodes
// for one package would break every caller that had spelled this NodeID().
//
// Structural nodes -- modules and manifests -- are not packages and get "",
// which resolves to a nil package rather than to some other node's entry.
func NodePackageRef(node sdk.GraphNode) string {
	dep, ok := sdk.AsDependencyNode(node)
	if !ok {
		return ""
	}
	if ref := strings.TrimSpace(dep.PackageRef); ref != "" {
		return ref
	}
	return strings.TrimSpace(dep.NodeID())
}

// RegistryPackageForNode returns what the matching stage recorded for the
// package a graph node resolved to, or nil when it recorded nothing.
func RegistryPackageForNode(registry *sdk.PackageRegistry, node sdk.GraphNode) *sdk.Package {
	return RegistryPackage(registry, NodePackageRef(node))
}

// FindingVulnerabilityID returns the advisory id a finding references.
//
// A finding's own id is the advisory id for the vulnerability auditor, which
// mints one finding per advisory, but not for auditors that mint several
// findings against one advisory; those carry it in VulnerabilityID. Every join
// from a finding to an advisory uses this precedence.
func FindingVulnerabilityID(f sdk.Finding) string {
	return resolvedVulnerabilityID(f.VulnerabilityID, f.ID)
}

// resolvedVulnerabilityID is the rule itself, shared with the AuditFinding
// projection so the document and the joins against it cannot answer
// differently.
func resolvedVulnerabilityID(vulnerabilityID, findingID string) string {
	if id := strings.TrimSpace(vulnerabilityID); id != "" {
		return id
	}
	return strings.TrimSpace(findingID)
}

// PackageAdvisory returns the advisory a package carries under the given id,
// matching aliases as well, or nil when it carries none.
//
// Aliases matter because the id a finding names is the id of the source that
// reported it: an OSV finding names GHSA-xxxx while the enriched advisory may
// be stored under its CVE, and an exact-id-only match silently renders the
// finding without severity, fix version, or KEV status.
func PackageAdvisory(pkg *sdk.Package, vulnerabilityID string) *sdk.Vulnerability {
	vulnerabilityID = strings.TrimSpace(vulnerabilityID)
	if pkg == nil || vulnerabilityID == "" {
		return nil
	}
	for i := range pkg.Vulnerabilities {
		vuln := &pkg.Vulnerabilities[i]
		if vuln.ID == vulnerabilityID {
			return vuln
		}
		if slices.Contains(vuln.Aliases, vulnerabilityID) {
			return vuln
		}
	}
	return nil
}

// FindingAdvisory resolves a finding against the registry, returning the
// package it references and the advisory it names. Either may be nil: an
// unenriched scan has neither, and a license or policy finding has a package
// but names no advisory.
func FindingAdvisory(registry *sdk.PackageRegistry, f sdk.Finding) (*sdk.Package, *sdk.Vulnerability) {
	pkg := RegistryPackage(registry, f.PackageRef)
	return pkg, PackageAdvisory(pkg, FindingVulnerabilityID(f))
}

// ResolvedLicenses returns the licenses to show for a graph node: the ones
// matching learned when it learned any, and otherwise the ones detection read
// out of the lockfile or manifest.
//
// Matching wins as a whole rather than merging, because a registry package's
// licenses are the reconciled answer for that PURL and detection's are one
// producer's reading of one file.
func ResolvedLicenses(registry *sdk.PackageRegistry, node sdk.GraphNode) []sdk.PackageLicense {
	if pkg := RegistryPackageForNode(registry, node); pkg != nil && len(pkg.Licenses) > 0 {
		return pkg.Licenses
	}
	dep, _ := sdk.AsDependencyNode(node)
	return sdk.DetectionLicenses(dep)
}

// NodeVulnerabilities returns the advisories the matching stage recorded
// against the package a graph node resolved to.
func NodeVulnerabilities(registry *sdk.PackageRegistry, node sdk.GraphNode) []sdk.Vulnerability {
	pkg := RegistryPackageForNode(registry, node)
	if pkg == nil {
		return nil
	}
	return pkg.Vulnerabilities
}

// IdentifyPackageRef resolves the display identity of a package reference:
// what a table cell, a finding header, or an MCP payload should call it.
//
// When matching knew the package its own record answers. When it did not, the
// reference is itself a package URL and already carries the answer, so the
// fallback parses it rather than printing it: a findings table that says
// "pkg:npm/%40scope/deep@2.0.0" where every other row says "@scope/deep" is
// showing the reader a key, not a name. Parsing and the ecosystem-native
// spelling are purlkit's and the SDK's jobs, not this file's -- there is no
// PURL grammar here.
//
// The raw reference survives as Name only when it is not a package URL at all,
// which is the one case where there is nothing better to show.
//
// The return type is FindingPackageRef because findings were the first surface
// to need this shape; it is the presentation identity of any package reference.
func IdentifyPackageRef(registry *sdk.PackageRegistry, packageRef string) FindingPackageRef {
	packageRef = strings.TrimSpace(packageRef)
	if pkg := RegistryPackage(registry, packageRef); pkg != nil {
		return FindingPackageRef{
			Name:      pkg.DisplayName(),
			Org:       pkg.Org,
			Version:   pkg.Version,
			Purl:      pkg.PURL,
			Ecosystem: string(pkg.Ecosystem),
		}
	}
	return identityFromPURL(packageRef)
}

// identityFromPURL derives a display identity from a package URL, falling back
// to the raw string when it is not one.
func identityFromPURL(packageRef string) FindingPackageRef {
	parsed, err := purlkit.Parse(packageRef)
	if err != nil || parsed.Name == "" {
		return FindingPackageRef{Name: packageRef, Purl: packageRef}
	}
	coords := sdk.Coordinates{
		PURL:    packageRef,
		Org:     parsed.Namespace,
		Name:    parsed.Name,
		Version: parsed.Version,
	}
	// The purl type is the only ecosystem signal a bare reference carries, and
	// purlkit owns the type-to-ecosystem table. An unmapped or deliberately
	// refused type (purlkit refuses "hex", which serves two languages) leaves
	// Ecosystem empty, and DisplayName then falls back to its neutral spelling
	// rather than guessing.
	if token, ok := purlkit.CanonicalEcosystem(parsed.Type); ok {
		if ecosystem, err := sdk.ParseEcosystem(token); err == nil {
			coords.Ecosystem = ecosystem
		}
	}
	// The same normalization node construction runs, for the same reason: a
	// purl namespace is not yet a Bomly org. npm's is spelled "@scope" there
	// and "scope" on coordinates, and DisplayName re-adds the marker -- so
	// without this the fallback renders "@@scope/deep".
	sdk.NormalizeCoordinates(&coords)
	return FindingPackageRef{
		Name:      coords.DisplayName(),
		Org:       coords.Org,
		Version:   coords.Version,
		Purl:      packageRef,
		Ecosystem: string(coords.Ecosystem),
	}
}
