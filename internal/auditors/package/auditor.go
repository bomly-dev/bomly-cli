package packageauditor

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const auditorName = "package"

// Auditor protects against denied packages and suspiciously similar package names.
type Auditor struct {
	DenyPackages       []string
	DenyGroups         []string
	ProtectedPackages  []string
	TyposquatThreshold float64
	TyposquatMode      string
	FailOnScopes       []sdk.Scope
}

func (a Auditor) Descriptor() sdk.AuditorDescriptor {
	return sdk.AuditorDescriptor{
		Name:    auditorName,
		Enabled: true,
		Origin:  sdk.CoreOrigin,
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
	packages := req.Graph.Nodes()
	if req.Target != nil {
		packages = []*sdk.Dependency{req.Target}
	}
	findings := make([]sdk.Finding, 0)
	baseNames := protectedNames(req.BaselineGraph, a.ProtectedPackages)
	baseIDs := packageIDs(req.BaselineGraph)
	threshold := a.TyposquatThreshold
	if threshold <= 0 {
		threshold = 0.90
	}

	baseDisplayNames := packageDisplayNames(req.BaselineGraph)

	for _, pkg := range packages {
		if pkg == nil || !scopeAllowed(pkg, a.FailOnScopes) {
			continue
		}
		if deniedPackage(pkg, a.DenyPackages) {
			findings = append(findings, finding(pkg, "denied-package", "Package is denylisted", sdk.FindingDispositionFail))
			continue
		}
		if deniedGroup(pkg, a.DenyGroups) {
			findings = append(findings, finding(pkg, "denied-group", "Package group is denylisted", sdk.FindingDispositionFail))
			continue
		}
		if _, existed := baseIDs[pkg.ID]; existed || req.BaselineGraph == nil {
			continue
		}
		// Skip typosquat check for packages whose name already existed in the
		// baseline (version-agnostic). A version bump of a known package is not
		// a typosquat candidate.
		if _, nameExisted := baseDisplayNames[strings.ToLower(strings.TrimSpace(pkg.DisplayName()))]; nameExisted {
			continue
		}
		if protected, score, ok := closestProtectedName(pkg.DisplayName(), baseNames, threshold); ok {
			disposition := sdk.FindingDispositionWarn
			if strings.EqualFold(strings.TrimSpace(a.TyposquatMode), "fail") {
				disposition = sdk.FindingDispositionFail
			}
			f := finding(pkg, "suspicious-package", fmt.Sprintf("Package name is %.2f similar to protected package %s", score, protected), disposition)
			f.Reasons = []string{"possible-typosquat"}
			findings = append(findings, f)
		}
	}
	return sdk.AuditResult{Findings: findings}, nil
}

func finding(pkg *sdk.Dependency, id, title string, disposition sdk.FindingDisposition) sdk.Finding {
	purl := pkg.PackageRef
	if purl == "" {
		purl = sdk.CanonicalPackageURLFromDependency(pkg)
	}
	return sdk.Finding{
		ID:             fmt.Sprintf("%s:%s:%s", auditorName, id, pkg.ID),
		Kind:           sdk.FindingKindPackage,
		Title:          title,
		Severity:       "unknown",
		Source:         auditorName,
		Auditor:        auditorName,
		Disposition:    disposition,
		PackageRef:     purl,
		DependencyRefs: []string{pkg.ID},
	}
}

func packageIDs(graph *sdk.Graph) map[string]struct{} {
	ids := make(map[string]struct{})
	if graph == nil {
		return ids
	}
	for _, pkg := range graph.Nodes() {
		if pkg != nil {
			ids[pkg.ID] = struct{}{}
		}
	}
	return ids
}

func packageDisplayNames(graph *sdk.Graph) map[string]struct{} {
	names := make(map[string]struct{})
	if graph == nil {
		return names
	}
	for _, pkg := range graph.Nodes() {
		if pkg != nil {
			names[strings.ToLower(strings.TrimSpace(pkg.DisplayName()))] = struct{}{}
		}
	}
	return names
}

func protectedNames(graph *sdk.Graph, configured []string) []string {
	names := append([]string(nil), configured...)
	if graph == nil {
		return names
	}
	for _, pkg := range graph.Nodes() {
		if pkg == nil {
			continue
		}
		names = append(names, pkg.DisplayName())
	}
	return names
}

func deniedPackage(pkg *sdk.Dependency, denied []string) bool {
	canonical := sdk.CanonicalPackageURLFromDependency(pkg)
	base := sdk.PackageURLBase(canonical)
	if canonical == "" || base == "" {
		return false
	}
	for _, candidate := range denied {
		canonicalCandidate := sdk.CanonicalizePackageURL(candidate)
		if canonicalCandidate == "" {
			continue
		}
		parsed := sdk.ParsePackageURL(canonicalCandidate)
		hasVersion := parsed != nil && strings.TrimSpace(parsed.Version) != ""
		if hasVersion && canonical == canonicalCandidate {
			return true
		}
		if !hasVersion && base == sdk.PackageURLBase(canonicalCandidate) {
			return true
		}
	}
	return false
}

func deniedGroup(pkg *sdk.Dependency, denied []string) bool {
	base := sdk.PackageURLBase(sdk.CanonicalPackageURLFromDependency(pkg))
	if base == "" {
		return false
	}
	for _, candidate := range denied {
		group := strings.TrimSuffix(sdk.PackageURLBase(candidate), "/")
		if group != "" && strings.HasPrefix(base, group+"/") {
			return true
		}
	}
	return false
}

func closestProtectedName(name string, protected []string, threshold float64) (string, float64, bool) {
	bestName := ""
	bestScore := 0.0
	for _, candidate := range protected {
		score := normalizedSimilarity(name, candidate)
		if score >= threshold && score < 1 && score > bestScore {
			bestName = candidate
			bestScore = score
		}
	}
	return bestName, bestScore, bestName != ""
}

func normalizedSimilarity(left, right string) float64 {
	left = strings.ToLower(strings.TrimSpace(left))
	right = strings.ToLower(strings.TrimSpace(right))
	if left == "" || right == "" {
		return 0
	}
	if left == right {
		return 1
	}
	if collapseComparableName(left) == collapseComparableName(right) {
		return 0.96
	}
	distance := levenshteinDistance(left, right)
	maxLen := maxInt(len(left), len(right))
	if maxLen == 0 {
		return 0
	}
	return math.Max(0, 1-float64(distance)/float64(maxLen))
}

func collapseComparableName(value string) string {
	replacer := strings.NewReplacer("-", "", "_", "", ".", "", " ", "")
	return replacer.Replace(strings.ToLower(strings.TrimSpace(value)))
}

func levenshteinDistance(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = minInt(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func minInt(values ...int) int {
	best := values[0]
	for _, value := range values[1:] {
		if value < best {
			best = value
		}
	}
	return best
}

func maxInt(values ...int) int {
	best := values[0]
	for _, value := range values[1:] {
		if value > best {
			best = value
		}
	}
	return best
}

func scopeAllowed(pkg *sdk.Dependency, allowed []sdk.Scope) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if pkg.HasScope(candidate) {
			return true
		}
	}
	return false
}
