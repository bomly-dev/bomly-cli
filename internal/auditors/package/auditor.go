package packageauditor

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-sdk/purlkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

const auditorName = "package"

// Auditor protects against denied packages and suspiciously similar package names.
type Auditor struct {
	DenyPackages       []string
	DenyGroups         []string
	ProtectedPackages  []string
	FailOn             []model.FailOnConstraint
	TyposquatThreshold float64
	TyposquatMode      string
}

func (a Auditor) Descriptor() plugin.AuditorDescriptor {
	return plugin.AuditorDescriptor{
		// No SupportedEcosystems: deny rules match on package name and group,
		// and the typosquat corpus is the baseline graph itself rather than a
		// per-ecosystem package list.
		Name: auditorName,
	}
}

func (a Auditor) Ready(context.Context, plugin.AuditRequest) error {
	return nil
}

func (a Auditor) Applicable(_ context.Context, req plugin.AuditRequest) (bool, error) {
	if req.AuditorFilter.Excludes(auditorName) {
		return false, nil
	}
	if len(req.AuditorFilter.Include) > 0 && !req.AuditorFilter.Includes(auditorName) {
		return false, nil
	}
	return true, nil
}

func (a Auditor) Audit(_ context.Context, req plugin.AuditRequest) (plugin.AuditResult, error) {
	findings := dependencySourceChangeFindings(req.DependencyDetailChanges, a.FailOn)
	if req.Graph == nil {
		return plugin.AuditResult{Findings: findings}, nil
	}
	packages := req.Graph.DependencyNodes()
	if req.Target != nil {
		packages = []*model.DependencyNode{req.Target}
	}
	baseNames := protectedNames(req.BaselineGraph, a.ProtectedPackages)
	baseIDs := packageIDs(req.BaselineGraph)
	threshold := a.TyposquatThreshold
	if threshold <= 0 {
		threshold = 0.90
	}

	baseDisplayNames := packageDisplayNames(req.BaselineGraph)

	for _, pkg := range packages {
		if pkg == nil {
			continue
		}
		if deniedPackage(pkg, a.DenyPackages) {
			findings = append(findings, finding(pkg, "denied-package", "Package is denylisted", model.FindingPolicyStatusFail))
			continue
		}
		if deniedGroup(pkg, a.DenyGroups) {
			findings = append(findings, finding(pkg, "denied-group", "Package group is denylisted", model.FindingPolicyStatusFail))
			continue
		}
		if _, existed := baseIDs[pkg.NodeID()]; existed {
			continue
		}
		// Skip typosquat check for packages whose name already existed in the
		// baseline (version-agnostic). A version bump of a known package is not
		// a typosquat candidate.
		if _, nameExisted := baseDisplayNames[strings.ToLower(strings.TrimSpace(pkg.DisplayName()))]; nameExisted {
			continue
		}
		if protected, score, ok := closestProtectedName(pkg.DisplayName(), baseNames, threshold); ok {
			policyStatus := model.FindingPolicyStatusWarn
			if strings.EqualFold(strings.TrimSpace(a.TyposquatMode), "fail") {
				policyStatus = model.FindingPolicyStatusFail
			}
			f := finding(pkg, "suspicious-package", fmt.Sprintf("Package name is %.2f similar to protected package %s", score, protected), policyStatus)
			f.Reasons = []string{"possible-typosquat"}
			findings = append(findings, f)
		}
	}
	return plugin.AuditResult{Findings: findings}, nil
}

func dependencySourceChangeFindings(transitions []model.DependencyDetailTransition, constraints []model.FailOnConstraint) []model.Finding {
	type findingKey struct {
		ruleID   string
		identity string
	}
	grouped := make(map[findingKey]*model.Finding)
	for _, transition := range transitions {
		if transition.After == nil {
			continue
		}
		for _, reason := range transition.ReviewReasons() {
			var ruleID, title string
			switch reason {
			case model.DependencyDetailReviewSourceGit:
				ruleID = "dependency-source-change-to-git"
				title = "Dependency source changed to Git; registry-based vulnerability checks may no longer cover it"
			case model.DependencyDetailReviewSourceURL:
				ruleID = "dependency-source-change-to-url"
				title = "Dependency source changed to a URL; registry-based vulnerability checks may no longer cover it"
			default:
				continue
			}
			purl := transition.After.PackageRef
			if purl == "" {
				purl = transition.After.NodeID()
			}
			identity := purl
			if identity == "" {
				identity = transition.After.NodeID()
			}
			status := model.FindingPolicyStatusWarn
			if sourceChangeMatchesConstraints(constraints) {
				status = model.FindingPolicyStatusFail
			}
			key := findingKey{ruleID: ruleID, identity: identity}
			if existing := grouped[key]; existing != nil {
				existing.DependencyRefs = appendUniqueString(existing.DependencyRefs, transition.After.NodeID())
				continue
			}
			grouped[key] = &model.Finding{
				ID:             fmt.Sprintf("%s:%s:%s", auditorName, ruleID, identity),
				Kind:           model.FindingKindPackage,
				Title:          title,
				Severity:       packageFindingSeverity(status),
				Reasons:        []string{string(reason)},
				Source:         auditorName,
				Auditor:        auditorName,
				RuleID:         ruleID,
				PolicyStatus:   status,
				PackageRef:     purl,
				DependencyRefs: appendUniqueString(nil, transition.After.NodeID()),
			}
		}
	}
	keys := make([]findingKey, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ruleID != keys[j].ruleID {
			return keys[i].ruleID < keys[j].ruleID
		}
		return keys[i].identity < keys[j].identity
	})
	findings := make([]model.Finding, 0, len(keys))
	for _, key := range keys {
		finding := grouped[key]
		sort.Strings(finding.DependencyRefs)
		findings = append(findings, *finding)
	}
	return findings
}

func sourceChangeMatchesConstraints(constraints []model.FailOnConstraint) bool {
	for _, candidate := range constraints {
		if candidate.Kind == model.SourceChangeConstraint && candidate.Value == model.SourceChangeValue {
			return true
		}
	}
	return false
}

func appendUniqueString(values []string, value string) []string {
	if strings.TrimSpace(value) == "" {
		return values
	}
	if slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}

func finding(pkg *model.DependencyNode, id, title string, policyStatus model.FindingPolicyStatus) model.Finding {
	purl := pkg.PackageRef
	if purl == "" {
		purl = pkg.NodeID()
	}
	return model.Finding{
		ID:             fmt.Sprintf("%s:%s:%s", auditorName, id, pkg.NodeID()),
		Kind:           model.FindingKindPackage,
		Title:          title,
		Severity:       packageFindingSeverity(policyStatus),
		Source:         auditorName,
		Auditor:        auditorName,
		RuleID:         id,
		PolicyStatus:   policyStatus,
		PackageRef:     purl,
		DependencyRefs: []string{pkg.NodeID()},
	}
}

// packageFindingSeverity maps a finding's policy status to a GitHub-aligned
// severity: a policy failure is an Error, an advisory finding is a Warning.
func packageFindingSeverity(policyStatus model.FindingPolicyStatus) model.SeverityLevel {
	if policyStatus == model.FindingPolicyStatusWarn {
		return model.SeverityWarning
	}
	return model.SeverityError
}

func packageIDs(graph *model.Graph) map[string]struct{} {
	ids := make(map[string]struct{})
	if graph == nil {
		return ids
	}
	for _, pkg := range graph.DependencyNodes() {
		if pkg != nil {
			ids[pkg.NodeID()] = struct{}{}
		}
	}
	return ids
}

func packageDisplayNames(graph *model.Graph) map[string]struct{} {
	names := make(map[string]struct{})
	if graph == nil {
		return names
	}
	for _, pkg := range graph.DependencyNodes() {
		if pkg != nil {
			names[strings.ToLower(strings.TrimSpace(pkg.DisplayName()))] = struct{}{}
		}
	}
	return names
}

func protectedNames(graph *model.Graph, configured []string) []string {
	names := append([]string(nil), configured...)
	if graph == nil {
		return names
	}
	for _, pkg := range graph.DependencyNodes() {
		if pkg == nil {
			continue
		}
		names = append(names, pkg.DisplayName())
	}
	return names
}

func deniedPackage(pkg *model.DependencyNode, denied []string) bool {
	canonical := pkg.NodeID()
	base := model.PackageURLBase(canonical)
	if canonical == "" || base == "" {
		return false
	}
	for _, candidate := range denied {
		canonicalCandidate := model.CanonicalizePackageURL(candidate)
		if canonicalCandidate == "" {
			continue
		}
		parsed := purlkitParse(canonicalCandidate)
		hasVersion := parsed != nil && strings.TrimSpace(parsed.Version) != ""
		if hasVersion && canonical == canonicalCandidate {
			return true
		}
		if !hasVersion && base == model.PackageURLBase(canonicalCandidate) {
			return true
		}
	}
	return false
}

func deniedGroup(pkg *model.DependencyNode, denied []string) bool {
	base := model.PackageURLBase(pkg.NodeID())
	if base == "" {
		return false
	}
	for _, candidate := range denied {
		group := strings.TrimSuffix(model.PackageURLBase(candidate), "/")
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

// purlkitParse delegates to purlkit, the SDK's kit over the official
// packageurl-go. sdk.ParsePackageURL was the deprecated anchore-fork entry
// point and is gone; it returned nil on failure, so this keeps that shape.
func purlkitParse(value string) *purlkit.PURL {
	parsed, err := purlkit.Parse(value)
	if err != nil {
		return nil
	}
	return &parsed
}
