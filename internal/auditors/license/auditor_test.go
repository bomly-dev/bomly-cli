package license

import (
	"context"
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
			result, err := tt.auditor.Audit(context.Background(), sdk.AuditRequest{Graph: g, Registry: registry, Mode: sdk.TargetModeFullGraph})
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
