package mcp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-sdk"
)

// remediationInput carries everything the compact builders need to turn raw
// findings into ranked remediation groups.
type remediationInput struct {
	Findings  []sdk.Finding
	Graph     *sdk.Graph
	Registry  *sdk.PackageRegistry
	Manifests []output.ScanManifest
	// FocusedRemediation limits explain projections to suggestions already
	// filtered for the focused dependency occurrence.
	FocusedRemediation *sdk.PackageRemediation
	// IncludeReachability gates the reachability field on compact findings
	// (only meaningful when the analyze stage ran).
	IncludeReachability bool
}

// remediationOutput is the classified, grouped, capped projection of the
// input findings.
type remediationOutput struct {
	Remediations  []RemediationGroup
	Informational []CompactFinding
	Truncation    *TruncationInfo
}

// buildRemediations projects canonical package remediation suggestions into
// compact groups and keeps audit-only findings informational. It does not
// choose actions or package-manager advice; enrichment already made those
// decisions in internal/remediation.
func buildRemediations(in remediationInput) remediationOutput {
	trunc := &TruncationInfo{}
	visibleFindings := map[string]struct{}{}
	omittedFindings := map[string]struct{}{}
	var informational []CompactFinding
	findingsByPackage := make(map[string][]CompactFinding)

	for _, f := range in.Findings {
		vuln := lookupFindingVulnerability(in.Registry, f)
		compact, _ := buildCompactFinding(f, vuln, in)
		if f.Kind != sdk.FindingKindVulnerability || f.PackageRef == "" ||
			f.PolicyStatus == sdk.FindingPolicyStatusWarn ||
			f.PolicyStatus == sdk.FindingPolicyStatusSuppressed {
			appendInformational(&informational, compact, visibleFindings, omittedFindings)
			continue
		}
		findingsByPackage[f.PackageRef] = append(findingsByPackage[f.PackageRef], compact)
	}

	var groups []RemediationGroup
	for _, pkg := range packagesWithRemediation(in.Registry) {
		fixes := findingsByPackage[pkg.PURL]
		if len(fixes) == 0 {
			continue
		}
		sortCompactFindings(fixes)
		packageRemediation := pkg.Remediation
		if in.FocusedRemediation != nil {
			packageRemediation = in.FocusedRemediation
		}
		if packageRemediation == nil || len(packageRemediation.Suggestions) == 0 {
			for _, fix := range fixes {
				appendInformational(&informational, fix, visibleFindings, omittedFindings)
			}
			delete(findingsByPackage, pkg.PURL)
			continue
		}
		for _, suggestion := range packageRemediation.Suggestions {
			if len(groups) >= maxRemediationGroups {
				trunc.OmittedGroups++
				recordCompactFindings(omittedFindings, fixes)
				continue
			}
			group := canonicalRemediationGroup(pkg, packageRemediation, suggestion, fixes, in)
			if len(group.Fixes) > maxFindingsPerGroup {
				recordCompactFindings(omittedFindings, group.Fixes[maxFindingsPerGroup:])
				group.Fixes = append([]CompactFinding(nil), group.Fixes[:maxFindingsPerGroup]...)
			}
			recordCompactFindings(visibleFindings, group.Fixes)
			finalizeCanonicalGroup(&group)
			groups = append(groups, group)
		}
		delete(findingsByPackage, pkg.PURL)
	}
	leftoverPackageRefs := make([]string, 0, len(findingsByPackage))
	for packageRef := range findingsByPackage {
		leftoverPackageRefs = append(leftoverPackageRefs, packageRef)
	}
	sort.Strings(leftoverPackageRefs)
	for _, packageRef := range leftoverPackageRefs {
		fixes := findingsByPackage[packageRef]
		sortCompactFindings(fixes)
		for _, fix := range fixes {
			appendInformational(&informational, fix, visibleFindings, omittedFindings)
		}
	}
	rankGroups(groups)
	sortCompactFindings(informational)
	for key := range visibleFindings {
		delete(omittedFindings, key)
	}
	trunc.OmittedFindings = len(omittedFindings)

	if trunc.OmittedFindings == 0 && trunc.OmittedGroups == 0 {
		trunc = nil
	} else {
		trunc.Truncated = true
		trunc.Note = "response was capped; re-scan a narrower path or use bomly_explain per package for the rest"
	}
	return remediationOutput{Remediations: groups, Informational: informational, Truncation: trunc}
}

func appendInformational(
	findings *[]CompactFinding,
	finding CompactFinding,
	visible map[string]struct{},
	omitted map[string]struct{},
) {
	if len(*findings) < maxInformational {
		*findings = append(*findings, finding)
		visible[compactFindingKey(finding)] = struct{}{}
		return
	}
	omitted[compactFindingKey(finding)] = struct{}{}
}

func recordCompactFindings(target map[string]struct{}, findings []CompactFinding) {
	for _, finding := range findings {
		target[compactFindingKey(finding)] = struct{}{}
	}
}

func compactFindingKey(finding CompactFinding) string {
	return strings.Join([]string{
		finding.Package.Purl,
		finding.Package.Label(),
		finding.Kind,
		finding.RuleID,
		finding.VulnID,
	}, "\x00")
}

func packagesWithRemediation(registry *sdk.PackageRegistry) []*sdk.Package {
	if registry == nil {
		return nil
	}
	packages := registry.All()
	sort.SliceStable(packages, func(i, j int) bool {
		return packages[i].PURL < packages[j].PURL
	})
	return packages
}

func canonicalRemediationGroup(
	pkg *sdk.Package,
	packageRemediation *sdk.PackageRemediation,
	suggestion sdk.PackageRemediationSuggestion,
	fixes []CompactFinding,
	in remediationInput,
) RemediationGroup {
	target := packageIdentityFromRegistry(in.Registry, pkg.PURL)
	targetRef := suggestion.SuggestedActionDependencyRef
	if targetRef == "" && len(suggestion.AffectedDependencyRefs) > 0 {
		targetRef = suggestion.AffectedDependencyRefs[0]
	}
	if in.Graph != nil {
		if dependency, ok := in.Graph.Node(targetRef); ok {
			target = packageIdentityFromDependency(dependency)
		}
	}
	group := RemediationGroup{
		Action:         string(suggestion.Action),
		TargetPackage:  target,
		ManifestPath:   suggestion.ManifestPath,
		OverrideAdvice: suggestion.OverrideAdvice,
		Fixes:          compactFixesForSuggestion(fixes, suggestion, in.Graph),
	}
	if manifest := manifestForDependency(in.Manifests, targetRef); manifest != nil {
		group.PackageManager = manifest.PackageManager.Name()
		if group.ManifestPath == "" {
			group.ManifestPath = manifest.Path
		}
	}
	if packageRemediation.Status == sdk.PackageRemediationComplete {
		group.RecommendedVersion = packageRemediation.RecommendedVersion
	}
	return group
}

func compactFixesForSuggestion(
	fixes []CompactFinding,
	suggestion sdk.PackageRemediationSuggestion,
	graph *sdk.Graph,
) []CompactFinding {
	out := append([]CompactFinding(nil), fixes...)
	if graph == nil || len(suggestion.AffectedDependencyRefs) == 0 {
		return out
	}
	dependency, ok := graph.Node(suggestion.AffectedDependencyRefs[0])
	if !ok || dependency == nil {
		return out
	}
	for idx := range out {
		out[idx].Direct = nil
		out[idx].ShortestPath = nil
		if dependency.Relationship == sdk.DependencyRelationshipUnknown {
			continue
		}
		path := shortestPathToRoot(graph, dependency.ID)
		if len(path) == 0 {
			continue
		}
		direct := dependency.Relationship == sdk.DependencyRelationshipDirect
		out[idx].Direct = &direct
		out[idx].ShortestPath = pathLabels(path)
	}
	return out
}

// ancestorTarget identifies the direct dependency an agent should change to
// remediate a (possibly transitive) vulnerable package, plus the manifest
// that declares it.
type ancestorTarget struct {
	identity         PackageIdentity
	dependencyID     string
	direct           bool
	manifestPath     string
	packageManager   string
	unresolvedParent bool
}

// buildCompactFinding projects one finding (and its resolved advisory) into
// the compact shape and resolves its shortest dependency path and direct
// ancestor.
func buildCompactFinding(f sdk.Finding, vuln *sdk.Vulnerability, in remediationInput) (CompactFinding, ancestorTarget) {
	compact := CompactFinding{
		VulnID:         findingVulnID(f),
		Kind:           string(f.Kind),
		Severity:       string(f.Severity),
		RuleID:         f.RuleID,
		PolicyStatus:   string(f.PolicyStatus),
		Classification: classifyFinding(f, vuln),
		Title:          f.Title,
		Package:        packageIdentityFromRegistry(in.Registry, f.PackageRef),
	}
	if vuln != nil {
		if compact.Severity == "" {
			compact.Severity = string(vuln.ParsedSeverity)
		}
		compact.Aliases = capStrings(vuln.Aliases, maxAliases)
		compact.FixedIn = maxFixedInVersion([]sdk.Vulnerability{*vuln})
		compact.KEV = vuln.KEVExploited
		compact.EPSS = topEPSS(vuln.EPSS)
		if in.IncludeReachability && vuln.Reachability != nil {
			compact.Reachability = string(vuln.Reachability.Status)
		}
	}

	node := resolveGraphNode(in.Graph, f)
	// Without graph placement we cannot name a different ancestor, so the
	// package itself is the direct remediation target.
	ancestor := ancestorTarget{identity: compact.Package, direct: true}
	if node != nil {
		if node.Relationship == sdk.DependencyRelationshipUnknown {
			compact.Direct = nil
			ancestor.direct = false
			ancestor.identity = packageIdentityFromDependency(node)
			ancestor.dependencyID = node.ID
			ancestor.unresolvedParent = true
		} else {
			path := shortestPathToRoot(in.Graph, node.ID)
			if len(path) > 0 {
				direct := len(path) <= 2
				compact.Direct = &direct
				compact.ShortestPath = pathLabels(path)
				ancestor.direct = direct
				ancestorNode := path[len(path)-1]
				if !direct && len(path) >= 2 {
					ancestorNode = path[1]
				}
				ancestor.identity = packageIdentityFromDependency(ancestorNode)
				ancestor.dependencyID = ancestorNode.ID
			}
		}
	}
	if ancestor.dependencyID == "" && node != nil {
		ancestor.dependencyID = node.ID
	}
	if manifest := manifestForDependency(in.Manifests, ancestor.dependencyID); manifest != nil {
		ancestor.manifestPath = manifest.Path
		ancestor.packageManager = manifest.PackageManager.Name()
	}
	return compact, ancestor
}

// finalizeCanonicalGroup adds presentation prose to canonical structured
// data. It does not choose or alter the action, version, or manager advice.
func finalizeCanonicalGroup(group *RemediationGroup) {
	sortCompactFindings(group.Fixes)
	ids := make([]string, 0, len(group.Fixes))
	for _, fix := range group.Fixes {
		ids = append(ids, fix.VulnID)
	}
	label := strings.Join(ids, ", ")

	switch group.Action {
	case ActionDirectBump:
		if group.RecommendedVersion != "" {
			group.Recommendation = fmt.Sprintf(
				"Update `%s` to %s in %s.",
				group.TargetPackage.Name,
				group.RecommendedVersion,
				valueOr(group.ManifestPath, "its manifest"),
			)
		}
	case ActionTransitiveOverride, ActionLockfileRefresh:
		if group.OverrideAdvice != "" {
			group.Recommendation = group.OverrideAdvice
		} else {
			group.Recommendation = fmt.Sprintf(
				"Refresh the resolved version in %s.",
				valueOr(group.ManifestPath, "the owning manifest"),
			)
		}
	case ActionNoFixUpstream:
		group.Recommendation = fmt.Sprintf("No fixed version is available upstream for %s.", label)
	case ActionManualReview:
		group.Recommendation = "Review the package and owning manifest; available evidence does not support a concrete change."
	}
}

// remediationFindings joins enriched vulnerabilities with optional audit
// findings. Enrichment supplies complete vulnerability coverage. When audit
// ran, enriched vulnerabilities omitted by policy remain visible with a
// suppressed status instead of resurfacing as actionable suggestions.
func remediationFindings(
	registry *sdk.PackageRegistry,
	auditFindings []sdk.Finding,
	auditRan bool,
) []sdk.Finding {
	used := make([]bool, len(auditFindings))
	result := make([]sdk.Finding, 0, len(auditFindings))
	if registry != nil {
		for _, pkg := range registry.All() {
			if pkg == nil {
				continue
			}
			for _, vulnerability := range pkg.Vulnerabilities {
				finding := sdk.Finding{
					ID:              vulnerability.ID,
					Kind:            sdk.FindingKindVulnerability,
					Title:           firstNonEmpty(vulnerability.Title, vulnerability.Summary, vulnerability.ID),
					Severity:        vulnerability.ParsedSeverity,
					Source:          vulnerability.Source,
					Auditor:         "enrichment",
					PackageRef:      pkg.PURL,
					VulnerabilityID: vulnerability.ID,
				}
				if auditRan {
					finding.PolicyStatus = sdk.FindingPolicyStatusSuppressed
				}
				for idx, candidate := range auditFindings {
					if used[idx] || candidate.Kind != sdk.FindingKindVulnerability ||
						candidate.PackageRef != pkg.PURL ||
						!findingIdentifiesVulnerability(candidate, vulnerability) {
						continue
					}
					finding = candidate.Clone()
					if finding.ID == "" {
						finding.ID = vulnerability.ID
					}
					if finding.Title == "" {
						finding.Title = firstNonEmpty(vulnerability.Title, vulnerability.Summary, vulnerability.ID)
					}
					if finding.Severity == "" {
						finding.Severity = vulnerability.ParsedSeverity
					}
					if finding.Source == "" {
						finding.Source = vulnerability.Source
					}
					if finding.VulnerabilityID == "" {
						finding.VulnerabilityID = vulnerability.ID
					}
					used[idx] = true
					break
				}
				result = append(result, finding)
			}
		}
	}
	for idx, finding := range auditFindings {
		if !used[idx] {
			result = append(result, finding.Clone())
		}
	}
	return result
}

func findingIdentifiesVulnerability(finding sdk.Finding, vulnerability sdk.Vulnerability) bool {
	identity := strings.ToLower(strings.TrimSpace(findingVulnID(finding)))
	if identity == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(vulnerability.ID), identity) {
		return true
	}
	for _, alias := range vulnerability.Aliases {
		if strings.EqualFold(strings.TrimSpace(alias), identity) {
			return true
		}
	}
	return false
}

// rankGroups orders remediation groups most-urgent first: known-exploited
// (KEV) findings, then max severity, then top EPSS score, then actions with a
// fix before no-fix, then by how many findings the change closes.
func rankGroups(groups []RemediationGroup) {
	score := func(g RemediationGroup) (kev bool, severity int, epss float64) {
		for _, f := range g.Fixes {
			kev = kev || f.KEV
			if rank := sdk.SeverityRank(sdk.SeverityLevel(f.Severity)); rank > severity {
				severity = rank
			}
			if f.EPSS > epss {
				epss = f.EPSS
			}
		}
		return kev, severity, epss
	}
	actionRank := func(action string) int {
		switch action {
		case ActionDirectBump:
			return 0
		case ActionTransitiveOverride, ActionLockfileRefresh:
			return 1
		case ActionManualReview:
			return 2
		default: // no-fix-upstream last — nothing to do right now
			return 3
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		iKEV, iSev, iEPSS := score(groups[i])
		jKEV, jSev, jEPSS := score(groups[j])
		if iKEV != jKEV {
			return iKEV
		}
		if iSev != jSev {
			return iSev > jSev
		}
		if iEPSS != jEPSS {
			return iEPSS > jEPSS
		}
		if actionRank(groups[i].Action) != actionRank(groups[j].Action) {
			return actionRank(groups[i].Action) < actionRank(groups[j].Action)
		}
		if len(groups[i].Fixes) != len(groups[j].Fixes) {
			return len(groups[i].Fixes) > len(groups[j].Fixes)
		}
		return groups[i].TargetPackage.Label() < groups[j].TargetPackage.Label()
	})
}

func sortCompactFindings(findings []CompactFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		iSev := sdk.SeverityRank(sdk.SeverityLevel(findings[i].Severity))
		jSev := sdk.SeverityRank(sdk.SeverityLevel(findings[j].Severity))
		if iSev != jSev {
			return iSev > jSev
		}
		if findings[i].VulnID != findings[j].VulnID {
			return findings[i].VulnID < findings[j].VulnID
		}
		return findings[i].Package.Label() < findings[j].Package.Label()
	})
}

// --- graph and registry resolution -----------------------------------------

// resolveGraphNode finds the graph node a finding refers to: first via
// DependencyRefs (node IDs recorded by the auditor), then by PURL match.
func resolveGraphNode(g *sdk.Graph, f sdk.Finding) *sdk.Dependency {
	if g == nil {
		return nil
	}
	for _, ref := range f.DependencyRefs {
		if node, ok := g.Node(ref); ok {
			return node
		}
	}
	if f.PackageRef == "" {
		return nil
	}
	var match *sdk.Dependency
	g.WalkNodes(func(node *sdk.Dependency) bool {
		if node != nil && node.PURL == f.PackageRef {
			match = node
			return false
		}
		return true
	})
	return match
}

// shortestPathToRoot returns the shortest root→target chain for a node using
// a bounded upward BFS over reverse edges. It never enumerates all paths
// (that is exponential on dense graphs). Returns nil when the node is
// unknown; returns [target] when the target itself is a root.
func shortestPathToRoot(g *sdk.Graph, targetID string) []*sdk.Dependency {
	if g == nil {
		return nil
	}
	target, ok := g.Node(targetID)
	if !ok {
		return nil
	}
	rootIDs := map[string]struct{}{}
	for _, root := range g.Roots() {
		if root != nil {
			rootIDs[root.ID] = struct{}{}
		}
	}
	if _, isRoot := rootIDs[targetID]; isRoot || len(rootIDs) == 0 {
		return []*sdk.Dependency{target}
	}

	// BFS upward from the target through Dependents until a root is reached.
	parentOf := map[string]string{targetID: ""}
	queue := []string{targetID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		dependents, err := g.Dependents(current)
		if err != nil {
			continue
		}
		for _, dependent := range dependents {
			if dependent == nil {
				continue
			}
			if _, visited := parentOf[dependent.ID]; visited {
				continue
			}
			parentOf[dependent.ID] = current
			if _, isRoot := rootIDs[dependent.ID]; isRoot {
				return chainFrom(g, dependent.ID, parentOf)
			}
			queue = append(queue, dependent.ID)
		}
	}
	// No root reachable (disconnected component): report the node alone.
	return []*sdk.Dependency{target}
}

// chainFrom walks parentOf pointers from a root back down to the target,
// producing the root→target node chain.
func chainFrom(g *sdk.Graph, rootID string, parentOf map[string]string) []*sdk.Dependency {
	var chain []*sdk.Dependency
	for id := rootID; id != ""; id = parentOf[id] {
		node, ok := g.Node(id)
		if !ok {
			return nil
		}
		chain = append(chain, node)
	}
	return chain
}

func pathLabels(path []*sdk.Dependency) []string {
	labels := make([]string, 0, len(path))
	for idx, node := range path {
		if idx == maxPathNodes-1 && len(path) > maxPathNodes {
			labels = append(labels, fmt.Sprintf("… (+%d more hops)", len(path)-maxPathNodes))
			labels = append(labels, dependencyLabel(path[len(path)-1]))
			break
		}
		labels = append(labels, dependencyLabel(node))
	}
	return labels
}

func dependencyLabel(dep *sdk.Dependency) string {
	if dep == nil {
		return ""
	}
	name := dep.DisplayName()
	if dep.Version != "" && !strings.HasSuffix(name, "@"+dep.Version) {
		return name + "@" + dep.Version
	}
	return name
}

func manifestForDependency(manifests []output.ScanManifest, dependencyID string) *output.ScanManifest {
	if dependencyID == "" {
		return nil
	}
	for idx := range manifests {
		for _, dep := range manifests[idx].Dependencies {
			if dep.ID == dependencyID {
				return &manifests[idx]
			}
		}
	}
	return nil
}

func packageIdentityFromRegistry(registry *sdk.PackageRegistry, purl string) PackageIdentity {
	if registry != nil {
		if pkg, ok := registry.Get(purl); ok && pkg != nil {
			return PackageIdentity{
				Name:      pkg.DisplayName(),
				Org:       pkg.Org,
				Version:   pkg.Version,
				Purl:      pkg.PURL,
				Ecosystem: string(pkg.Ecosystem),
			}
		}
	}
	return PackageIdentity{Name: purl, Purl: purl}
}

func packageIdentityFromDependency(dep *sdk.Dependency) PackageIdentity {
	if dep == nil {
		return PackageIdentity{}
	}
	return PackageIdentity{
		Name:      dep.DisplayName(),
		Org:       dep.Org,
		Version:   dep.Version,
		Purl:      dep.PURL,
		Ecosystem: string(dep.Ecosystem),
	}
}

// lookupFindingVulnerability resolves the advisory a finding references
// (PackageRef + VulnerabilityID, matching aliases too) against the registry.
func lookupFindingVulnerability(registry *sdk.PackageRegistry, f sdk.Finding) *sdk.Vulnerability {
	if registry == nil || f.PackageRef == "" {
		return nil
	}
	pkg, ok := registry.Get(f.PackageRef)
	if !ok || pkg == nil {
		return nil
	}
	vulnID := findingVulnID(f)
	if vulnID == "" {
		return nil
	}
	for idx := range pkg.Vulnerabilities {
		v := &pkg.Vulnerabilities[idx]
		if v.ID == vulnID {
			return v
		}
		for _, alias := range v.Aliases {
			if alias == vulnID {
				return v
			}
		}
	}
	return nil
}

func findingVulnID(f sdk.Finding) string {
	if f.VulnerabilityID != "" {
		return f.VulnerabilityID
	}
	return f.ID
}

// --- small helpers ----------------------------------------------------------

// maxFixedInVersion returns the highest FixedIn version across vulns, using
// semver comparison when parseable and falling back to the first non-empty
// value otherwise.
func maxFixedInVersion(vulns []sdk.Vulnerability) string {
	best := ""
	for _, v := range vulns {
		best = higherVersion(best, v.FixedIn)
	}
	return best
}

// higherVersion returns the semver-greater of two version strings; when
// either side does not parse, the first non-empty value wins.
func higherVersion(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	av, aErr := semver.NewVersion(a)
	bv, bErr := semver.NewVersion(b)
	if aErr != nil || bErr != nil {
		return a
	}
	if bv.GreaterThan(av) {
		return b
	}
	return a
}

func topEPSS(scores []sdk.EPSSScore) float64 {
	top := 0.0
	for _, score := range scores {
		if score.EPSS > top {
			top = score.EPSS
		}
	}
	return top
}

func capStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return append([]string(nil), values...)
	}
	return append([]string(nil), values[:limit]...)
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
