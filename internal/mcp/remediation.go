package mcp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// remediationInput carries everything the compact builders need to turn raw
// findings into ranked remediation groups.
type remediationInput struct {
	Findings  []sdk.Finding
	Graph     *sdk.Graph
	Registry  *sdk.PackageRegistry
	Manifests []output.ScanManifest
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

// buildRemediations classifies findings into actionable remediation groups
// ("this one change closes these N findings") and informational entries,
// applying the compact caps. Grouping key: the direct dependency to change
// plus the manifest that declares it.
func buildRemediations(in remediationInput) remediationOutput {
	trunc := &TruncationInfo{}
	groups := map[string]*RemediationGroup{}
	var groupKeys []string
	var informational []CompactFinding

	for _, f := range in.Findings {
		vuln := lookupFindingVulnerability(in.Registry, f)
		compact, ancestor := buildCompactFinding(f, vuln, in)
		classification := compact.Classification

		// Warning-status findings are informational — except cheap wins
		// (fix available), which agents should still see as actionable.
		if !findingFails(f) && classification != ClassificationFixAvailable {
			if len(informational) < maxInformational {
				informational = append(informational, compact)
			} else {
				trunc.OmittedFindings++
			}
			continue
		}

		action := remediationAction(f, vuln, compact, ancestor, ancestor.packageManager)
		key := remediationGroupKey(action, ancestor, compact)
		group, ok := groups[key]
		if !ok {
			if len(groups) >= maxRemediationGroups {
				trunc.OmittedGroups++
				trunc.OmittedFindings++
				continue
			}
			group = &RemediationGroup{Action: action, TargetPackage: ancestor.identity}
			group.ManifestPath = ancestor.manifestPath
			group.PackageManager = ancestor.packageManager
			groups[key] = group
			groupKeys = append(groupKeys, key)
		}
		if len(group.Fixes) >= maxFindingsPerGroup {
			trunc.OmittedFindings++
			continue
		}
		group.Fixes = append(group.Fixes, compact)
	}

	out := make([]RemediationGroup, 0, len(groups))
	for _, key := range groupKeys {
		group := groups[key]
		finalizeGroup(group, in.Registry)
		out = append(out, *group)
	}
	rankGroups(out)
	sortCompactFindings(informational)

	if trunc.OmittedFindings == 0 && trunc.OmittedGroups == 0 {
		trunc = nil
	} else {
		trunc.Truncated = true
		trunc.Note = "response was capped; re-scan a narrower path or use bomly_explain per package for the rest"
	}
	return remediationOutput{Remediations: out, Informational: informational, Truncation: trunc}
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

// remediationAction decides what kind of change closes the finding: a direct
// version bump, a declarative override on the transitive dependency, a
// lockfile refresh for managers without overrides, a policy review, or —
// when upstream has released nothing — no fix at all.
func remediationAction(f sdk.Finding, vuln *sdk.Vulnerability, compact CompactFinding, ancestor ancestorTarget, packageManager string) string {
	if f.Kind != sdk.FindingKindVulnerability {
		return ActionPolicyReview
	}
	if ancestor.unresolvedParent {
		return ActionManualReview
	}
	switch compact.Classification {
	case ClassificationWontFix, ClassificationNoFixUpstream, ClassificationUnknown:
		if vuln == nil || maxFixedInVersion([]sdk.Vulnerability{*vuln}) == "" {
			return ActionNoFixUpstream
		}
	}
	if ancestor.direct {
		return ActionDirectBump
	}
	if _, supported := overrideAdvice(packageManager, compact.Package, "x", ""); supported {
		return ActionTransitiveOverride
	}
	return ActionLockfileRefresh
}

func remediationGroupKey(action string, ancestor ancestorTarget, compact CompactFinding) string {
	target := ancestor.identity.Purl
	if target == "" {
		target = ancestor.identity.Label()
	}
	if action == ActionNoFixUpstream || action == ActionManualReview || action == ActionPolicyReview {
		// No-fix and policy groups key on the affected package itself.
		target = compact.Package.Purl
		if target == "" {
			target = compact.Package.Label()
		}
	}
	return action + "\x00" + ancestor.manifestPath + "\x00" + target
}

// finalizeGroup computes the recommended version and recommendation text
// once the group's findings are complete.
func finalizeGroup(group *RemediationGroup, registry *sdk.PackageRegistry) {
	sortCompactFindings(group.Fixes)
	ids := make([]string, 0, len(group.Fixes))
	for _, fix := range group.Fixes {
		ids = append(ids, fix.VulnID)
	}
	recommendedVersion := groupRecommendedVersion(group.Fixes, registry)
	label := strings.Join(ids, ", ")

	switch group.Action {
	case ActionDirectBump:
		// The structured fields say it all for a direct bump; prose is only
		// added when no single safe version could be computed.
		group.RecommendedVersion = recommendedVersion
		if recommendedVersion == "" {
			group.Recommendation = fmt.Sprintf("Upgrade `%s` in %s to address %s; no single safe version was computed.",
				group.TargetPackage.Name, valueOr(group.ManifestPath, "its manifest"), label)
		}
	case ActionTransitiveOverride, ActionLockfileRefresh:
		group.RecommendedVersion = recommendedVersion
		group.OverrideAdvice = groupOverrideAdvice(group)
		verb := "override the transitive version"
		if group.Action == ActionLockfileRefresh {
			verb = "refresh the resolved version"
		}
		detail := ""
		if group.OverrideAdvice != "" {
			detail = ": " + group.OverrideAdvice
		}
		group.Recommendation = fmt.Sprintf(
			"Introduced via direct dependency `%s@%s` in %s: %s%s. Alternatively upgrade `%s` to a release that pulls a patched version.",
			group.TargetPackage.Name, group.TargetPackage.Version, valueOr(group.ManifestPath, "its manifest"),
			verb, detail, group.TargetPackage.Name)
	case ActionNoFixUpstream:
		group.Recommendation = fmt.Sprintf(
			"No fixed version released for %s. Remove or replace the dependency, or acknowledge via allow_vulnerability_ids.", label)
	case ActionManualReview:
		group.Recommendation = "The dependency is real, but its declaring parent could not be recovered. Review the owning manifest before selecting a change."
	case ActionPolicyReview:
		group.Recommendation = "Policy finding: requires review, not fixed by a version upgrade."
	}
}

// groupRecommendedVersion uses the shared package remediation summary only
// when every fix in the group belongs to one affected package with complete
// evidence. Parent grouping and policy findings must not invent a version.
func groupRecommendedVersion(fixes []CompactFinding, registry *sdk.PackageRegistry) string {
	if len(fixes) == 0 || registry == nil {
		return ""
	}
	purl := fixes[0].Package.Purl
	if purl == "" {
		return ""
	}
	for _, fix := range fixes[1:] {
		if fix.Package.Purl != purl {
			return ""
		}
	}
	pkg, ok := registry.Get(purl)
	if !ok || pkg == nil || pkg.Remediation == nil ||
		pkg.Remediation.Status != sdk.PackageRemediationComplete {
		return ""
	}
	return pkg.Remediation.RecommendedVersion
}

// remediationFindings joins enriched vulnerabilities with optional audit
// findings. Enrichment supplies complete vulnerability coverage; audit
// findings overlay policy fields without filtering out unaudited advisories.
func remediationFindings(registry *sdk.PackageRegistry, auditFindings []sdk.Finding) []sdk.Finding {
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
		case ActionManualReview, ActionPolicyReview:
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

// groupOverrideAdvice renders package-manager-specific override advice for
// each distinct fixable package in the group (capped at three). Multiple
// advisories on the same package collapse to its highest fixed version.
func groupOverrideAdvice(group *RemediationGroup) string {
	versionByPackage := map[string]string{}
	var order []string
	for _, fix := range group.Fixes {
		if fix.FixedIn == "" {
			continue
		}
		key := fix.Package.Label()
		if _, ok := versionByPackage[key]; !ok {
			order = append(order, key)
		}
		versionByPackage[key] = higherVersion(versionByPackage[key], fix.FixedIn)
	}
	var advices []string
	rendered := map[string]PackageIdentity{}
	for _, fix := range group.Fixes {
		key := fix.Package.Label()
		if _, ok := rendered[key]; ok {
			continue
		}
		rendered[key] = fix.Package
	}
	for _, key := range order {
		advice, _ := overrideAdvice(group.PackageManager, rendered[key], versionByPackage[key], group.ManifestPath)
		advices = append(advices, advice)
		if len(advices) == 3 {
			break
		}
	}
	return strings.Join(advices, "; ")
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

func affectedPackagesLabel(fixes []CompactFinding) string {
	seen := map[string]struct{}{}
	var labels []string
	for _, fix := range fixes {
		label := "`" + fix.Package.Label() + "`"
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		labels = append(labels, label)
	}
	return strings.Join(labels, ", ")
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
