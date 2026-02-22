// Package licenses contains shared helpers for external license-checker implementations.
package licenses

import (
	"strings"

	"github.com/bomly/bomly-cli/internal/model"
)

// MissingLicensePackages returns the packages eligible for external license lookup.
func MissingLicensePackages(packages []*model.Package) []*model.Package {
	eligible := make([]*model.Package, 0, len(packages))
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
func NormalizeLicenseSet(values []string, sourceType string) []model.PackageLicense {
	out := make([]model.PackageLicense, 0, len(values))
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
		out = append(out, model.PackageLicense{
			Value:          normalized,
			SPDXExpression: normalized,
			Type:           sourceType,
		})
	}
	return out
}
