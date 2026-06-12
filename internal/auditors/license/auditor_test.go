package license

import (
	"context"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestLicenseAuditorAllowDeny(t *testing.T) {
	allow := Auditor{AllowLicenses: []string{"MIT"}}
	deny := Auditor{DenyLicenses: []string{"GPL-3.0-only"}}

	// mkScenario builds an app→lib graph plus a registry where lib's package
	// (keyed by its PURL) carries the given license.
	mkScenario := func(license string) (*sdk.Graph, *sdk.PackageRegistry) {
		g := sdk.New()
		root := sdk.NewDependencyRefWithID("app@1.0.0", "app", "1.0.0")
		_ = g.AddNode(root)
		dep := sdk.NewDependency(sdk.Dependency{Name: "lib", Version: "1.0.0", Ecosystem: "npm", BuildSystem: "npm"})
		purl := sdk.CanonicalPackageURLFromDependency(dep)
		dep.PackageRef = purl
		_ = g.AddNode(dep)
		_ = g.AddEdge(root.ID, dep.ID)

		registry := sdk.NewPackageRegistry()
		registry.Ensure(purl).Licenses = []sdk.PackageLicense{{SPDXExpression: license}}
		return g, registry
	}

	tests := []struct {
		name        string
		auditor     Auditor
		license     string
		wantFinding bool
	}{
		{"allow satisfied", allow, "MIT", false},
		{"allow violated", allow, "GPL-3.0-only", true},
		{"deny violated", deny, "GPL-3.0-only", true},
		{"deny satisfied", deny, "Apache-2.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, registry := mkScenario(tt.license)
			result, err := tt.auditor.Audit(context.Background(), sdk.AuditRequest{Graph: g, Registry: registry})
			if err != nil {
				t.Fatalf("Audit() error = %v", err)
			}
			hasFinding := false
			for _, f := range result.Findings {
				if f.Kind == sdk.FindingKindLicense {
					hasFinding = true
				}
			}
			if hasFinding != tt.wantFinding {
				t.Errorf("want finding=%v got=%v", tt.wantFinding, hasFinding)
			}
		})
	}
}

func TestLicenseAuditorUnknownLicenseUsesCompactFindingID(t *testing.T) {
	g := sdk.New()
	root := sdk.NewDependencyRefWithID("app@1.0.0", "app", "1.0.0")
	_ = g.AddNode(root)
	dep := sdk.NewDependency(sdk.Dependency{
		Name:        "very-long-package-name-with-output-hostile-length",
		Version:     "1.2.3",
		Ecosystem:   "npm",
		BuildSystem: "npm",
	})
	purl := sdk.CanonicalPackageURLFromDependency(dep)
	dep.PackageRef = purl
	_ = g.AddNode(dep)
	_ = g.AddEdge(root.ID, dep.ID)

	result, err := Auditor{}.Audit(context.Background(), sdk.AuditRequest{
		Graph:    g,
		Registry: sdk.NewPackageRegistry(),
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %#v", result.Findings)
	}
	finding := result.Findings[0]
	if finding.ID != unknownLicenseFindingID {
		t.Fatalf("finding ID = %q, want %q", finding.ID, unknownLicenseFindingID)
	}
	if strings.Contains(finding.ID, dep.Name) || strings.Contains(finding.ID, purl) {
		t.Fatalf("finding ID should not include package identity: %q", finding.ID)
	}
	if finding.PackageRef != purl {
		t.Fatalf("finding package ref = %q, want %q", finding.PackageRef, purl)
	}
}
