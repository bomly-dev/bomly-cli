package license

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/github/go-spdx/v2/spdxexp"
)

const (
	auditorName             = "license"
	unknownLicenseFindingID = "UNKNOWN"
	licenseSeverityNA       = "n/a"
)

// Auditor evaluates package licenses against allow/deny SPDX policy.
type Auditor struct {
	AllowLicenses  []string
	DenyLicenses   []string
	ExemptPackages []string
}

func (a Auditor) Descriptor() sdk.AuditorDescriptor {
	return sdk.AuditorDescriptor{
		Name: auditorName,
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
	if req.Graph == nil || req.Registry == nil {
		return sdk.AuditResult{}, nil
	}
	deps := req.Graph.Nodes()
	if req.Target != nil {
		deps = []*sdk.Dependency{req.Target}
	}

	// Root packages are the project itself — they rarely declare a license in
	// lockfile data; flagging them generates non-actionable noise. Treat roots
	// as implicitly exempt from full-graph audits.
	rootIDs := map[string]struct{}{}
	if req.Target == nil {
		for _, r := range req.Graph.Roots() {
			if r != nil {
				rootIDs[r.ID] = struct{}{}
			}
		}
	}

	// One finding per offending PURL; the first dependency instance carries the
	// reference set.
	seenPURL := make(map[string]struct{}, len(deps))
	findings := make([]sdk.Finding, 0)
	for _, dep := range deps {
		if dep == nil || packageExempt(dep, a.ExemptPackages) {
			continue
		}
		if _, isRoot := rootIDs[dep.ID]; isRoot {
			continue
		}
		purl := dep.PackageRef
		if purl == "" {
			purl = sdk.CanonicalPackageURLFromDependency(dep)
		}
		if purl == "" {
			continue
		}
		if _, done := seenPURL[purl]; done {
			continue
		}
		seenPURL[purl] = struct{}{}

		licenses := registryLicenseValues(req.Registry, purl)
		if len(licenses) == 0 {
			findings = append(findings, finding(purl, dep.ID, "unknown-license", "Package license is unknown", sdk.FindingDispositionWarn))
			continue
		}
		valid, invalid := spdxexp.ValidateLicenses(licenses)
		if !valid {
			findings = append(findings, finding(purl, dep.ID, "invalid-license", "Package has invalid SPDX license: "+strings.Join(invalid, ", "), sdk.FindingDispositionFail))
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
				findings = append(findings, finding(purl, dep.ID, "denied-license", "Package license is not allowlisted", sdk.FindingDispositionFail))
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
					findings = append(findings, finding(purl, dep.ID, "denied-license", "Package license is denylisted", sdk.FindingDispositionFail))
					break
				}
			}
		}
	}
	return sdk.AuditResult{Findings: findings}, nil
}

func registryLicenseValues(registry *sdk.PackageRegistry, purl string) []string {
	pkg, ok := registry.Get(purl)
	if !ok || pkg == nil {
		return nil
	}
	return pkg.LicenseValues()
}

func finding(purl, depID, id, title string, disposition sdk.FindingDisposition) sdk.Finding {
	findingID := fmt.Sprintf("%s:%s:%s", auditorName, id, purl)
	if id == "unknown-license" {
		findingID = unknownLicenseID(purl)
	}
	f := sdk.Finding{
		ID:          findingID,
		Kind:        sdk.FindingKindLicense,
		Title:       title,
		Severity:    licenseSeverityNA,
		Source:      auditorName,
		Auditor:     auditorName,
		Disposition: disposition,
		PackageRef:  purl,
	}
	if depID != "" {
		f.DependencyRefs = []string{depID}
	}
	return f
}

func unknownLicenseID(purl string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(purl)))
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))
	if len(encoded) > 12 {
		encoded = encoded[:12]
	}
	if len(encoded) < 12 {
		return unknownLicenseFindingID + "-" + encoded
	}
	return fmt.Sprintf("%s-%s-%s-%s", unknownLicenseFindingID, encoded[:4], encoded[4:8], encoded[8:12])
}

func packageExempt(dep *sdk.Dependency, exemptions []string) bool {
	base := sdk.PackageURLBase(sdk.CanonicalPackageURLFromDependency(dep))
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
