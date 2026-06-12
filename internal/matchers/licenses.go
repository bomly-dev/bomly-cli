// Package matchers contain shared contracts and helper functions for matcher
// implementations.
package matchers

import (
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// MissingLicensePackages returns the packages eligible for external license lookup.
func MissingLicensePackages(packages []*sdk.Package) []*sdk.Package {
	eligible := make([]*sdk.Package, 0, len(packages))
	for _, pkg := range packages {
		if pkg == nil || len(pkg.Licenses) > 0 {
			continue
		}
		if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
			continue
		}
		eligible = append(eligible, pkg)
	}
	return eligible
}

// NormalizeLicenseSet converts raw license strings into Bomly package licenses.
func NormalizeLicenseSet(values []string, sourceType string) []sdk.PackageLicense {
	out := make([]sdk.PackageLicense, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, sdk.PackageLicense{
			Value:          normalized,
			SPDXExpression: normalized,
			Type:           sdk.LicenseType(sourceType),
		})
	}
	return out
}
