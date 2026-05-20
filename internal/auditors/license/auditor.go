package license

import (
	"context"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/github/go-spdx/v2/spdxexp"
)

const auditorName = "license"

// Auditor evaluates package licenses against allow/deny SPDX policy.
type Auditor struct {
	AllowLicenses  []string
	DenyLicenses   []string
	ExemptPackages []string
	FailOnScopes   []sdk.Scope
}

func (a Auditor) Descriptor() sdk.AuditorDescriptor {
	return sdk.AuditorDescriptor{
		Name:           auditorName,
		Enabled:        true,
		Origin:         sdk.CoreOrigin,
		SupportedModes: []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
	}
}

func (a Auditor) Ready() bool {
	return true
}

func (a Auditor) Applicable(_ context.Context, req sdk.AuditRequest) (bool, error) {
	if req.AuditorFilter.Excludes(auditorName) {
		return false, nil
	}
	if len(req.AuditorFilter.Include) > 0 && !req.AuditorFilter.Includes(auditorName) {
		return false, nil
	}
	return true, nil
}

func (a Auditor) Audit(_ context.Context, req sdk.AuditRequest) (sdk.AuditResult, error) {
	if req.Graph == nil {
		return sdk.AuditResult{}, nil
	}
	packages := req.Graph.Packages()
	if req.Mode == sdk.TargetModeComponent && req.Target != nil {
		packages = []*sdk.Package{req.Target}
	}

	// Root packages are the project itself (e.g. github.com/your/repo) —
	// they rarely declare a license in lockfile data and the license is
	// typically expressed at the repository level. Flagging the root with
	// "unknown-license" generates noise that is never actionable from
	// within a dependency manifest. We treat roots as implicitly exempt
	// for full-graph audits; component-mode audits (`req.Target != nil`)
	// still evaluate whatever target was passed in.
	rootIDs := map[string]struct{}{}
	if req.Mode != sdk.TargetModeComponent {
		for _, r := range req.Graph.Roots() {
			if r != nil {
				rootIDs[r.ID] = struct{}{}
			}
		}
	}

	findings := make([]sdk.Finding, 0)
	for _, pkg := range packages {
		if pkg == nil || !scopeAllowed(pkg, a.FailOnScopes) || packageExempt(pkg, a.ExemptPackages) {
			continue
		}
		if _, isRoot := rootIDs[pkg.ID]; isRoot {
			continue
		}
		licenses := pkg.LicenseValues()
		if len(licenses) == 0 {
			findings = append(findings, finding(pkg, "unknown-license", "Package license is unknown", sdk.FindingDispositionWarn))
			continue
		}
		valid, invalid := spdxexp.ValidateLicenses(licenses)
		if !valid {
			findings = append(findings, finding(pkg, "invalid-license", "Package has invalid SPDX license: "+strings.Join(invalid, ", "), sdk.FindingDispositionFail))
			continue
		}
		if len(a.AllowLicenses) > 0 {
			allowed := false
			for _, expr := range licenses {
				ok, err := spdxexp.Satisfies(expr, a.AllowLicenses)
				if err == nil && ok {
					allowed = true
					break
				}
			}
			if !allowed {
				findings = append(findings, finding(pkg, "denied-license", "Package license is not allowlisted", sdk.FindingDispositionFail))
			}
			continue
		}
		if len(a.DenyLicenses) > 0 {
			for _, expr := range licenses {
				used, err := spdxexp.ExtractLicenses(expr)
				if err != nil {
					continue
				}
				if intersectsLicenseList(used, a.DenyLicenses) {
					findings = append(findings, finding(pkg, "denied-license", "Package license is denylisted", sdk.FindingDispositionFail))
					break
				}
			}
		}
	}
	return sdk.AuditResult{Graph: req.Graph, Target: req.Target, Findings: findings}, nil
}

func finding(pkg *sdk.Package, id, title string, disposition sdk.FindingDisposition) sdk.Finding {
	return sdk.Finding{
		ID:          fmt.Sprintf("%s:%s:%s", auditorName, id, pkg.ID),
		Kind:        sdk.FindingKindLicense,
		Package:     pkg,
		Title:       title,
		Severity:    "unknown",
		Source:      auditorName,
		Auditor:     auditorName,
		Disposition: disposition,
	}
}

func packageExempt(pkg *sdk.Package, exemptions []string) bool {
	base := sdk.PackageURLBase(sdk.CanonicalPackageURLFromPackage(pkg))
	if base == "" {
		return false
	}
	for _, exemption := range exemptions {
		if base == sdk.PackageURLBase(exemption) {
			return true
		}
	}
	return false
}

func intersectsLicenseList(values, denied []string) bool {
	for _, value := range values {
		for _, candidate := range denied {
			if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(candidate)) {
				return true
			}
		}
	}
	return false
}

func scopeAllowed(pkg *sdk.Package, allowed []sdk.Scope) bool {
	if len(allowed) == 0 {
		return true
	}
	scope := sdk.Scope(pkg.Scope)
	for _, candidate := range allowed {
		if candidate == scope {
			return true
		}
	}
	return false
}
