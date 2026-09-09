package render

import (
	"strings"
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// The Findings table names packages the way every other surface does. It used
// to build the label from the registry's bare Name, which drops an npm scope --
// so the row read "deep@2.0.0" while the JSON document, the TUI and the MCP
// payload all said "@scope/deep@2.0.0", and a reader could not tell which of
// two similarly named packages the advisory was about.
func TestCompactFindingsNamePackagesTheWayEveryOtherSurfaceDoes(t *testing.T) {
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{Coordinates: sdk.Coordinates{
		PURL:      "pkg:npm/%40scope/deep@2.0.0",
		Ecosystem: sdk.EcosystemNPM,
		Org:       "scope",
		Name:      "deep",
		Version:   "2.0.0",
	}})

	findings := []sdk.Finding{{
		ID:         "GHSA-deep",
		Kind:       sdk.FindingKindVulnerability,
		Severity:   sdk.SeverityHigh,
		PackageRef: "pkg:npm/%40scope/deep@2.0.0",
	}}

	got := StripANSI(renderCompactFindings(findings, registry, false, false))
	if !strings.Contains(got, "@scope/deep@2.0.0") {
		t.Fatalf("findings table dropped the npm scope:\n%s", got)
	}
}

// An unenriched scan has no registry entry to read the name from, and the
// package reference is a package URL that already carries it.
func TestCompactFindingsNameUnenrichedPackagesFromTheirReference(t *testing.T) {
	findings := []sdk.Finding{{
		ID:         "GHSA-deep",
		Kind:       sdk.FindingKindVulnerability,
		Severity:   sdk.SeverityHigh,
		PackageRef: "pkg:npm/%40scope/deep@2.0.0",
	}}

	got := StripANSI(renderCompactFindings(findings, nil, false, false))
	if !strings.Contains(got, "@scope/deep@2.0.0") {
		t.Fatalf("findings table showed a lookup key instead of a name:\n%s", got)
	}
}
