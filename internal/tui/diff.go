package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

type diffStatus string

const (
	diffStatusAll     diffStatus = ""
	diffStatusAdded   diffStatus = "added"
	diffStatusRemoved diffStatus = "removed"
	diffStatusChanged diffStatus = "changed"
)

// componentsGroup names the cycling-axis for the Components tab. "status"
// groups Added/Changed/Removed; "manifest" groups by manifest (the old
// nested tree); "ecosystem" groups by ecosystem.
type componentsGroup string

const (
	componentsGroupStatus    componentsGroup = "status"
	componentsGroupManifest  componentsGroup = "manifest"
	componentsGroupEcosystem componentsGroup = "ecosystem"
)

type diffSourceSide string

const (
	diffSourceBase diffSourceSide = "base"
	diffSourceHead diffSourceSide = "head"
)

// diffModel renders the interactive `bomly diff` TUI. Tab cycling, the tab
// strip, and the top bar are owned by the embedded *shellModel; this struct
// holds diff payload data and per-tab state (filters, expansion maps).
type diffModel struct {
	*shellModel

	payload   output.DiffResponse
	baseGraph sdk.ConsolidatedGraph
	headGraph sdk.ConsolidatedGraph

	enrichEnabled bool

	componentsGroup        componentsGroup
	componentsRelationship string // "", "root", "direct", "transitive"
	componentsScope        string // "", "runtime", "development", "unset"
	componentsSeverity     string // "", "critical", "high", "medium", "low", "unknown"
	componentsEcosystem    string // "" or one of the known ecosystem names
	componentsExpanded     map[string]bool

	vulnGroup    string
	vulnExpanded map[string]bool

	licenseGroup    string
	licenseExpanded map[string]bool

	findingGroup    string
	findingExpanded map[string]bool

	postureGroup    string // "repository" (default) or "check"
	postureExpanded map[string]bool

	sourceSide         diffSourceSide
	sourceBaseExpanded map[string]bool
	sourceHeadExpanded map[string]bool
}

// NewDiff constructs the diff TUI model. baseGraph and headGraph are the
// consolidated graphs from the two pipeline runs; they feed the Source tab.
func NewDiff(payload output.DiffResponse, baseGraph, headGraph sdk.ConsolidatedGraph) *diffModel {
	m := &diffModel{
		payload:            payload,
		baseGraph:          baseGraph,
		headGraph:          headGraph,
		componentsGroup:    componentsGroupStatus,
		componentsExpanded: map[string]bool{},
		vulnGroup:          "status",
		vulnExpanded:       map[string]bool{},
		licenseGroup:       "license",
		licenseExpanded:    map[string]bool{},
		findingGroup:       "status",
		findingExpanded:    map[string]bool{},
		postureGroup:       "repository",
		postureExpanded:    map[string]bool{},
		sourceSide:         diffSourceBase,
		sourceBaseExpanded: map[string]bool{"root": true, "manifests": true},
		sourceHeadExpanded: map[string]bool{"root": true, "manifests": true},
	}
	m.shellModel = newShell(ShellSpec{
		TopBar: m.topBarLine,
		Tabs: []TabSpec{
			{ID: "overview", Label: "Overview", Build: m.buildOverviewTab},
			{ID: "components", Label: "Components", Build: m.buildComponentsTab},
			{ID: "vulnerabilities", Label: "Vulnerabilities", Build: m.buildVulnsTab},
			{ID: "licenses", Label: "Licenses", Build: m.buildLicensesTab},
			{ID: "findings", Label: "Findings", Build: m.buildFindingsTab},
			{ID: "posture", Label: "Posture", Build: m.buildPostureTab},
			{ID: "source", Label: "Source", Build: m.buildSourceTab},
		},
		Footer: func() (string, string) {
			return m.diffFooterSummary(), m.diffLegend()
		},
	})
	return m
}

// WithEnrichEnabled records whether enrichment ran, so empty Vuln/Findings
// tabs can distinguish "not requested" from "no matches".
func (m *diffModel) WithEnrichEnabled(enabled bool) *diffModel {
	if m == nil {
		return nil
	}
	m.enrichEnabled = enabled
	m.Rebuild()
	return m
}

// CycleGroup is the per-tab "g" key handler. Each tab interprets it
// differently (grouping axis, source-side focus).
func (m *diffModel) CycleGroup() {
	switch m.ActiveTabID() {
	case "components":
		m.componentsGroup = nextComponentsGroup(m.componentsGroup)
	case "vulnerabilities":
		m.vulnGroup = nextVulnGroup(m.vulnGroup)
	case "licenses":
		m.licenseGroup = nextLicenseGroup(m.licenseGroup)
	case "findings":
		m.findingGroup = nextFindingGroup(m.findingGroup)
	case "posture":
		m.postureGroup = cycleString(m.postureGroup, []string{"repository", "check"})
	case "source":
		if m.sourceSide == diffSourceBase {
			m.sourceSide = diffSourceHead
		} else {
			m.sourceSide = diffSourceBase
		}
	default:
		return
	}
	m.Rebuild()
}

// CycleRelationshipFilter advances the relationship filter on the Components
// tab (None → root → direct → transitive → None).
func (m *diffModel) CycleRelationshipFilter() {
	if m.ActiveTabID() != "components" {
		return
	}
	m.componentsRelationship = cycleString(m.componentsRelationship, []string{"", "root", "direct", "transitive"})
	m.Rebuild()
}

// CycleScopeFilter advances the scope filter (None → runtime → development → unset → None).
func (m *diffModel) CycleScopeFilter() {
	if m.ActiveTabID() != "components" {
		return
	}
	m.componentsScope = cycleString(m.componentsScope, []string{"", "runtime", "development", "unset"})
	m.Rebuild()
}

// CycleSeverityFilter advances the severity filter on the Components tab
// (driven by attached PackageRef.Vulnerabilities).
func (m *diffModel) CycleSeverityFilter() {
	if m.ActiveTabID() != "components" {
		return
	}
	m.componentsSeverity = cycleString(m.componentsSeverity, []string{"", "critical", "high", "medium", "low", "unknown"})
	m.Rebuild()
}

// CycleEcosystemFilter advances the ecosystem filter, drawn from the
// distinct ecosystems present across changed manifests.
func (m *diffModel) CycleEcosystemFilter() {
	if m.ActiveTabID() != "components" {
		return
	}
	ecos := map[string]struct{}{}
	for _, mf := range m.payload.Results.Manifests {
		if mf.Ecosystem != "" {
			ecos[mf.Ecosystem] = struct{}{}
		}
	}
	options := []string{""}
	for e := range ecos {
		options = append(options, e)
	}
	sort.Strings(options[1:])
	m.componentsEcosystem = cycleString(m.componentsEcosystem, options)
	m.Rebuild()
}

// nextComponentsGroup advances the Components-tab grouping axis through
// status → manifest → ecosystem → status.
func nextComponentsGroup(g componentsGroup) componentsGroup {
	switch g {
	case componentsGroupStatus:
		return componentsGroupManifest
	case componentsGroupManifest:
		return componentsGroupEcosystem
	default:
		return componentsGroupStatus
	}
}

func cycleString(current string, options []string) string {
	for i, opt := range options {
		if opt == current {
			return options[(i+1)%len(options)]
		}
	}
	return options[0]
}

// ToggleSelected toggles the expansion of the currently-focused tree node.
func (m *diffModel) ToggleSelected() { m.setSelectedExpansion(toggleExpansion) }

// ExpandSelected forces the focused node open.
func (m *diffModel) ExpandSelected() { m.setSelectedExpansion(forceExpand) }

// CollapseSelected forces the focused node closed.
func (m *diffModel) CollapseSelected() { m.setSelectedExpansion(forceCollapse) }

// ExpandAll opens every expandable node in the active tab.
func (m *diffModel) ExpandAll() { m.setAllExpansion(true) }

// CollapseAll closes every expandable node in the active tab.
func (m *diffModel) CollapseAll() { m.setAllExpansion(false) }

type expansionAction int

const (
	toggleExpansion expansionAction = iota
	forceExpand
	forceCollapse
)

func (m *diffModel) currentExpansionMap() map[string]bool {
	switch m.ActiveTabID() {
	case "components":
		return m.componentsExpanded
	case "vulnerabilities":
		return m.vulnExpanded
	case "licenses":
		return m.licenseExpanded
	case "findings":
		return m.findingExpanded
	case "posture":
		return m.postureExpanded
	case "source":
		if m.sourceSide == diffSourceBase {
			return m.sourceBaseExpanded
		}
		return m.sourceHeadExpanded
	}
	return nil
}

func (m *diffModel) setSelectedExpansion(action expansionAction) {
	expansion := m.currentExpansionMap()
	if expansion == nil {
		return
	}
	list := m.List()
	if list == nil {
		return
	}
	visible := list.visibleItemIndices()
	if len(visible) == 0 {
		return
	}
	item := list.items[visible[list.selectedVisibleIndex(visible)]]
	if !item.canOpen || item.key == "" {
		return
	}
	switch action {
	case toggleExpansion:
		expansion[item.key] = !item.expanded
	case forceExpand:
		if item.expanded {
			return
		}
		expansion[item.key] = true
	case forceCollapse:
		if !item.expanded {
			return
		}
		expansion[item.key] = false
	}
	m.rebuildPreserveSelection()
}

func (m *diffModel) setAllExpansion(expanded bool) {
	expansion := m.currentExpansionMap()
	if expansion == nil {
		return
	}
	list := m.List()
	if list == nil {
		return
	}
	for _, item := range list.items {
		if !item.canOpen || item.key == "" {
			continue
		}
		expansion[item.key] = expanded
	}
	m.rebuildPreserveSelection()
}

func (m *diffModel) rebuildPreserveSelection() {
	list := m.List()
	prevSelected := 0
	if list != nil {
		prevSelected = list.selected
	}
	m.Rebuild()
	if list := m.List(); list != nil {
		if prevSelected < len(list.items) {
			list.selected = prevSelected
		}
	}
}

// diffFooterSummary is the single-line stats bar pinned to the bottom of
// every diff tab. Each count is a *delta total* — items that changed
// between base and head — so the numbers add up to "what this diff
// represents." See diffAggregateCounts for the exact semantics.
func (m *diffModel) diffFooterSummary() string {
	c := m.diffAggregateCounts()
	return fmt.Sprintf("Manifests: %d | Packages: %d | Vulns: %d | Licenses: %d | Findings: %d",
		c.ManifestDeltas, c.PackageDeltas, c.VulnDeltas, c.LicenseUniqueDeltas, c.FindingDeltas)
}

// diffAggregateCounts holds the per-tab status-bar counts, broken out
// so they're individually testable. Every field is a "delta" — i.e.
// items affected by the diff — not a head-pipeline total.
//
// Semantics:
//
//	ManifestDeltas:       Added + Changed + Removed manifests.
//	PackageDeltas:        Added + Changed + Removed packages across all manifests.
//	VulnDeltas:           Introduced + Persisted + Resolved audit findings whose
//	                      Kind classifies them as a vulnerability (matches
//	                      isVulnerabilityFinding). Persisted is included because
//	                      the head pipeline still carries the vuln; the user
//	                      wants to see it in the per-diff vuln total.
//	LicenseUniqueDeltas:  Count of distinct SPDX identifiers that were either
//	                      introduced or retired. Same identifier introduced by
//	                      five packages counts ONCE.
//	FindingDeltas:        Introduced + Persisted + Resolved audit findings whose
//	                      Kind is NOT a vulnerability (policy/risk/license).
//	                      With the built-in policy auditor (which emits
//	                      Kind=vulnerability for every match), this is typically
//	                      zero — non-zero values come from external auditors or
//	                      future kinds.
type diffAggregateCounts struct {
	ManifestDeltas      int
	PackageDeltas       int
	VulnDeltas          int
	LicenseUniqueDeltas int
	FindingDeltas       int
}

func (m *diffModel) diffAggregateCounts() diffAggregateCounts {
	s := m.payload.Summary
	out := diffAggregateCounts{
		ManifestDeltas: s.AddedManifestCount + s.ChangedManifestCount + s.RemovedManifestCount,
		PackageDeltas:  s.AddedPackageCount + s.ChangedPackageCount + s.RemovedPackageCount,
	}
	if m.payload.Audit != nil {
		for _, bucket := range [][]output.AuditFinding{m.payload.Audit.Introduced, m.payload.Audit.Persisted, m.payload.Audit.Resolved} {
			for _, f := range bucket {
				if isVulnerabilityFinding(f) {
					out.VulnDeltas++
				} else {
					out.FindingDeltas++
				}
			}
		}
	}
	uniqueLicenses := make(map[string]struct{})
	for _, d := range m.collectLicenseDeltas() {
		uniqueLicenses[d.license] = struct{}{}
	}
	out.LicenseUniqueDeltas = len(uniqueLicenses)
	return out
}

// diffLegend mirrors scan's legend so the keyboard help row reads identical
// across commands.
func (m *diffModel) diffLegend() string {
	return strings.Join([]string{
		keyHint("Tab", "switch"),
		keyHint("Enter", "focus details"),
		keyHint("→", "expand"),
		keyHint("←", "collapse"),
		keyHint("]", "expand all"),
		keyHint("[", "collapse all"),
		keyHint("↑/↓", "move"),
		keyHint("q", "quit"),
	}, " ")
}

func (m *diffModel) topBarLine() string {
	parts := []string{
		render.Style(valueOrDash(m.payload.Project.Name), render.White, render.Bold),
		render.Style(targetKindLabel(m.payload.Project), render.Dim),
	}
	if m.payload.Project.TargetRef != "" {
		parts = append(parts, render.Style("ref: "+m.payload.Project.TargetRef, render.Cyan, render.Bold))
	}
	parts = append(parts, render.Style(m.payload.Comparison.Base+" -> "+m.payload.Comparison.Head, render.Cyan, render.Bold))
	return render.Style(" bomly ", render.BgCyan, render.Blue, render.Bold) + " " +
		render.Style("DIFF", render.BgBlue, render.White, render.Bold) + " " +
		strings.Join(parts, render.Style(" | ", render.Dim))
}

// --- Overview tab ---------------------------------------------------------

// View overrides the embedded shellModel.View so the Overview tab can
// render its custom dashboard layout. All other tabs (including Source,
// which uses listModel.bodyOverride for its two-pane body) fall through
// to the shared shellModel renderer so the chrome stays identical.
func (m *diffModel) View(width, height int) string {
	if m == nil || m.shellModel == nil {
		return ""
	}
	if m.ActiveTabID() == "overview" && !m.IsSearching() {
		return m.overviewDashboardView(width, height)
	}
	return m.shellModel.View(width, height) //nolint:staticcheck // explicit selector bypasses the View shadow on the embedding model
}

func (m *diffModel) buildOverviewTab() *listModel {
	summary := m.payload.Summary
	items := []listItem{
		{
			title:    "Comparison",
			subtitle: "overview",
			details: []string{
				render.Style("Comparison", render.Bold, render.Cyan),
				"",
				render.Style("  Base: ", render.Dim) + valueOrDash(m.payload.Comparison.Base),
				render.Style("  Head: ", render.Dim) + valueOrDash(m.payload.Comparison.Head),
				render.Style("  Project: ", render.Dim) + valueOrDash(m.payload.Project.Name),
				render.Style("  Target: ", render.Dim) + targetKindLabel(m.payload.Project),
			},
		},
		{
			title:    "Manifests",
			subtitle: "summary",
			details: []string{
				render.Style("Manifest Changes", render.Bold, render.Cyan),
				"",
				render.Style("  Added: ", render.Dim) + fmt.Sprintf("%d", summary.AddedManifestCount),
				render.Style("  Changed: ", render.Dim) + fmt.Sprintf("%d", summary.ChangedManifestCount),
				render.Style("  Removed: ", render.Dim) + fmt.Sprintf("%d", summary.RemovedManifestCount),
				render.Style("  Unchanged: ", render.Dim) + fmt.Sprintf("%d", summary.UnchangedManifestCount),
			},
		},
		{
			title:    "Packages",
			subtitle: "summary",
			details: []string{
				render.Style("Package Changes", render.Bold, render.Cyan),
				"",
				render.Style("  Added: ", render.Dim) + fmt.Sprintf("%d", summary.AddedPackageCount),
				render.Style("  Changed: ", render.Dim) + fmt.Sprintf("%d", summary.ChangedPackageCount),
				render.Style("  Removed: ", render.Dim) + fmt.Sprintf("%d", summary.RemovedPackageCount),
			},
		},
	}
	if m.payload.Audit != nil {
		items = append(items, listItem{
			title:    "Vulnerabilities",
			subtitle: "audit",
			details:  m.overviewAuditDetails(),
		})
		items = append(items, listItem{
			title:    "Audit Severity",
			subtitle: "distribution",
			details:  m.overviewAuditSummaryDetails(),
		})
	}
	items = append(items, listItem{
		title:    "Top Changed Manifests",
		subtitle: "top",
		details:  m.overviewTopChangedManifests(),
	})

	return &listModel{
		topPanels:      m.overviewPanels(),
		listTitle:      "Overview",
		detailTitle:    "Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Tab or 1-7 switches tabs; Esc clears search",
		emptyState:     "No diff overview is available.",
		items:          items,
	}
}

// diffOverviewStats aggregates everything the Overview dashboard needs.
// Every field is documented because the Overview's headline + distribution
// panes are easy to mis-aggregate. See computeOverviewStats for the
// authoritative source-of-truth comments per field.
type diffOverviewStats struct {
	// ecosystems: ecosystem -> number of change events (Added+Changed+Removed)
	// scoped to manifests in that ecosystem. Sum equals changedTotal.
	ecosystems map[string]int

	// scopes: composite key "<status> <scope>" (e.g. "added runtime") ->
	// number of change events. The composite key keeps the bar-chart
	// honest: a user can tell at a glance that direct-runtime additions
	// are different from runtime removals.
	scopes map[string]int

	// relationships: composite key "<status> <relationship>" (e.g. "removed
	// direct") -> number of change events. The relationship is looked up in
	// whichever graph the package belongs to: added/changed packages use
	// the HEAD graph; removed packages use the BASE graph (so removals
	// don't degenerate to "unknown").
	relationships map[string]int

	// licenseDeltas: "introduced"/"retired" -> count of license-delta EVENTS
	// (not unique IDs). Multiple packages contributing the same license each
	// add 1.
	licenseDeltas map[string]int

	// licenseUniqueIDs: SPDX id -> number of delta events referencing it.
	// `len(licenseUniqueIDs)` is the "unique licenses affected" count.
	licenseUniqueIDs map[string]int

	// findingsByKind: kind ("vulnerability", "license", "package") ->
	// total count across all three audit-delta buckets. Reads
	// AuditFinding.Kind directly. Powers the "Findings" summary card
	// in the Overview's top row.
	findingsByKind map[string]int

	// vulnByStatus: row key (severity, e.g. "critical") -> column map
	// (status -> count). Powers the "Vulnerability Findings" table.
	// Rows include every severity tier even when the bucket is zero so
	// the table layout stays stable across diffs.
	vulnByStatus map[string]map[string]int

	// licenseByStatus: rule key parsed from AuditFinding.ID for the license
	// auditor ("unknown", "invalid", "denied") -> status -> count. Powers
	// the "License Findings" table.
	licenseByStatus map[string]map[string]int

	// packageByStatus: rule key parsed from AuditFinding.ID for the package
	// auditor ("denied-package", "denied-group", "suspicious") -> status ->
	// count. Powers the "Package Findings" table.
	packageByStatus map[string]map[string]int

	// matchedExact: number of Changed entries that were NOT fuzzy-reconciled
	// (i.e. name match with version change).
	matchedExact int

	// matchedFuzzy: number of Changed entries reconciled by the fuzzy
	// matcher (PackageRef.Metadata["bomly.diff.fuzzy_reconciled"] == true).
	matchedFuzzy int

	// unmatchedAdded: total Added packages — entries that did NOT find a
	// peer in the base, even after fuzzy reconciliation. (Fuzzy matches are
	// moved out of Added/Removed into Changed at build time.)
	unmatchedAdded int

	// unmatchedRemoved: total Removed packages — see unmatchedAdded.
	unmatchedRemoved int

	// changedTotal: total package-level change events (Added+Changed+Removed).
	changedTotal int

	// auditSummaryTotal: the raw AuditSummary.Total field. Per
	// `internal/cli/scan_output.go` this is currently Introduced+Persisted
	// (Resolved is no longer added). Use it for "head state size" context;
	// the exit-code gate lives in auditVerdict.FailingIntroduced, NOT here.
	auditSummaryTotal int

	// auditRan: true when --enrich --audit produced an AuditSummary.
	auditRan bool
}

func (m *diffModel) computeOverviewStats() diffOverviewStats {
	out := diffOverviewStats{
		ecosystems:       make(map[string]int),
		scopes:           make(map[string]int),
		relationships:    make(map[string]int),
		licenseDeltas:    make(map[string]int),
		licenseUniqueIDs: make(map[string]int),
		findingsByKind:   make(map[string]int),
		vulnByStatus:     newRuleStatusTable(severityRowKeys()),
		licenseByStatus:  newRuleStatusTable(licenseRuleRowKeys()),
		packageByStatus:  newRuleStatusTable(packageRuleRowKeys()),
	}

	headRels := map[string]string{}
	if g, _ := graphFromConsolidated(m.headGraph); g != nil {
		headRels = classifyRelationships(g)
	}
	baseRels := map[string]string{}
	if g, _ := graphFromConsolidated(m.baseGraph); g != nil {
		baseRels = classifyRelationships(g)
	}

	// relForChange looks up a package's relationship in whichever graph it
	// belongs to. Added/Changed packages live in HEAD; removed packages live
	// in BASE; falling back across both keeps the bar-chart honest when
	// one side is missing (e.g. fuzzy-changed packages whose ID differs).
	relForChange := func(status, pkgID string) string {
		if status == "removed" {
			if r := baseRels[pkgID]; r != "" {
				return r
			}
			if r := headRels[pkgID]; r != "" {
				return r
			}
		} else {
			if r := headRels[pkgID]; r != "" {
				return r
			}
			if r := baseRels[pkgID]; r != "" {
				return r
			}
		}
		return "unknown"
	}

	addScopeRel := func(status string, scope string, pkgID string) {
		out.scopes[status+" "+scopeBucket(scope)]++
		out.relationships[status+" "+relForChange(status, pkgID)]++
	}

	for _, mf := range m.payload.Results.Manifests {
		eco := strings.TrimSpace(mf.Ecosystem)
		if eco == "" {
			eco = "unknown"
		}
		n := len(mf.Added) + len(mf.Changed) + len(mf.Removed)
		if n > 0 {
			out.ecosystems[eco] += n
			out.changedTotal += n
		}
		for _, change := range mf.Added {
			addScopeRel("added", change.Package.Scope, change.Package.ID)
		}
		for _, change := range mf.Removed {
			addScopeRel("removed", change.Package.Scope, change.Package.ID)
		}
		for _, change := range mf.Changed {
			addScopeRel("changed", change.After.Scope, change.After.ID)
			if isFuzzyReconciled(change.After) {
				out.matchedFuzzy++
			} else {
				out.matchedExact++
			}
		}
		out.unmatchedAdded += len(mf.Added)
		out.unmatchedRemoved += len(mf.Removed)
	}

	// License deltas (events + unique IDs).
	for _, d := range m.collectLicenseDeltas() {
		out.licenseDeltas[d.status]++
		out.licenseUniqueIDs[d.license]++
	}

	// Audit aggregations — walk all three delta buckets and split by
	// FindingKind. AuditFinding.Kind is the source of truth; the older
	// auditor-name heuristic ('vulnerability'/'license'/'package' as
	// strings) is no longer used.
	if m.payload.Audit != nil {
		out.auditRan = true
		if m.payload.Audit.AuditSummary != nil {
			out.auditSummaryTotal = m.payload.Audit.AuditSummary.Total
		}
		bucketStatus := []string{"introduced", "persisted", "resolved"}
		buckets := [][]output.AuditFinding{m.payload.Audit.Introduced, m.payload.Audit.Persisted, m.payload.Audit.Resolved}
		for bIdx, bucket := range buckets {
			status := bucketStatus[bIdx]
			for _, f := range bucket {
				kind := findingKindOf(f)
				out.findingsByKind[kind]++
				switch kind {
				case "vulnerability":
					sev := strings.ToLower(strings.TrimSpace(f.Severity))
					if _, ok := out.vulnByStatus[sev]; !ok {
						sev = "unknown"
					}
					out.vulnByStatus[sev][status]++
				case "license":
					rule := findingRule(f, "unknown")
					if _, ok := out.licenseByStatus[rule]; !ok {
						// Bucket unrecognized rules under "other" so the
						// pre-seeded table layout doesn't get extra rows
						// for novel plugin findings; the user still sees
						// the count.
						rule = "other"
						if _, ok := out.licenseByStatus[rule]; !ok {
							out.licenseByStatus[rule] = map[string]int{}
						}
					}
					out.licenseByStatus[rule][status]++
				case "package":
					rule := findingRule(f, "other")
					if _, ok := out.packageByStatus[rule]; !ok {
						rule = "other"
						if _, ok := out.packageByStatus[rule]; !ok {
							out.packageByStatus[rule] = map[string]int{}
						}
					}
					out.packageByStatus[rule][status]++
				}
			}
		}
	}
	return out
}

// auditStatusLabel maps the internal audit-delta status to its short
// user-facing word. Internal data continues to use the long forms
// ("introduced"/"persisted"/"resolved") so existing keys and sort
// orders stay stable, but the UI shows the shorter "new"/"old"/"fixed".
// License deltas use "introduced"/"retired" — only "introduced" overlaps
// and gets the same translation; "retired" passes through unchanged.
func auditStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "introduced":
		return "new"
	case "persisted":
		return "old"
	case "resolved":
		return "fixed"
	}
	return strings.ToLower(strings.TrimSpace(status))
}

// auditStatusTitle is auditStatusLabel with the first letter capitalised
// (for bucket headers and labels inside boxes).
func auditStatusTitle(status string) string {
	return titleCase(auditStatusLabel(status))
}

// findingKindOf returns the lowercased FindingKind for a finding, with a
// last-resort heuristic for payloads that omit the Kind field entirely
// (older diff outputs, external plugins). The fallback mirrors the
// classification done by isVulnerabilityFinding so this function and that
// predicate never disagree.
func findingKindOf(f output.AuditFinding) string {
	if k := strings.ToLower(strings.TrimSpace(f.Kind)); k != "" {
		switch k {
		case "vuln", "advisory", "cve":
			return "vulnerability"
		}
		return k
	}
	if isVulnerabilityFinding(f) {
		return "vulnerability"
	}
	switch strings.ToLower(strings.TrimSpace(f.Auditor)) {
	case "license":
		return "license"
	case "package":
		return "package"
	}
	return "other"
}

// findingRule pulls the rule keyword from an AuditFinding.ID. Built-in
// auditors format IDs as "<auditor>:<rule>:<package-id>" (see
// internal/auditors/{license,package}/auditor.go). The rule chunk is the
// 2nd colon-separated field; we additionally strip a trailing "-license"
// / "-package" so callers see consistent short keys ("unknown" instead
// of "unknown-license", "denied" instead of "denied-license").
func findingRule(f output.AuditFinding, fallback string) string {
	id := strings.TrimSpace(f.ID)
	if id == "" {
		return fallback
	}
	parts := strings.SplitN(id, ":", 3)
	if len(parts) < 2 {
		return fallback
	}
	rule := parts[1]
	rule = strings.TrimSuffix(rule, "-license")
	rule = strings.TrimSuffix(rule, "-package")
	if rule == "" {
		return fallback
	}
	return rule
}

// severityRowKeys / licenseRuleRowKeys / packageRuleRowKeys define the
// row layout (and visible order) for the corresponding Overview tables.
// They live alongside the renderer so adding a new severity tier or
// auditor rule is a single-spot change.
func severityRowKeys() []string {
	return []string{"critical", "high", "medium", "low", "unknown"}
}

func licenseRuleRowKeys() []string {
	// Mirrors the rule IDs in internal/auditors/license/auditor.go:
	//   unknown-license / invalid-license / denied-license
	// Plus an "other" row so external license auditors land somewhere.
	return []string{"unknown", "invalid", "denied", "other"}
}

func packageRuleRowKeys() []string {
	// Mirrors the rule IDs in internal/auditors/package/auditor.go:
	//   denied-package / denied-group / suspicious-package
	// Plus an "other" row for external package auditors.
	return []string{"denied", "denied-group", "suspicious", "other"}
}

// newRuleStatusTable pre-allocates an inner map for every known row so
// the table always renders the full set, even if a particular diff has
// zero findings on a row (the user sees "0 0 0" rather than the row
// vanishing).
func newRuleStatusTable(rows []string) map[string]map[string]int {
	out := make(map[string]map[string]int, len(rows))
	for _, r := range rows {
		out[r] = map[string]int{}
	}
	return out
}

func scopeBucket(scope string) string {
	s := strings.ToLower(strings.TrimSpace(scope))
	if s == "" {
		return "unset"
	}
	return s
}

func isFuzzyReconciled(pkg output.PackageRef) bool {
	if pkg.Metadata == nil {
		return false
	}
	v, ok := pkg.Metadata["bomly.diff.fuzzy_reconciled"]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// classifyRelationships labels every package in a graph as root, direct, or
// transitive. Roots are packages with no incoming edges; direct dependencies
// are immediate children of any root; everything else is transitive.
func classifyRelationships(g *sdk.Graph) map[string]string {
	out := make(map[string]string)
	if g == nil {
		return out
	}
	rootIDs := make(map[string]struct{})
	for _, r := range g.Roots() {
		if r == nil {
			continue
		}
		rootIDs[r.ID] = struct{}{}
		out[r.ID] = "root"
	}
	for rid := range rootIDs {
		deps, _ := g.DirectDependencies(rid)
		for _, d := range deps {
			if d == nil {
				continue
			}
			if _, isRoot := rootIDs[d.ID]; isRoot {
				continue
			}
			if _, alreadyLabeled := out[d.ID]; alreadyLabeled {
				continue
			}
			out[d.ID] = "direct"
		}
	}
	for _, pkg := range g.Nodes() {
		if pkg == nil {
			continue
		}
		if _, ok := out[pkg.ID]; !ok {
			out[pkg.ID] = "transitive"
		}
	}
	return out
}

// overviewHeadline renders the one-line headline above the panes. Each
// chip reports a *delta-scoped* fact. The "audit verdict" chip mirrors
// `internal/cli/diff_cmd.go:161-165`: FAIL iff at least one *introduced*
// finding's Disposition gates the exit code (i.e. `output.FailingFindingCount`
// returns > 0). Persisted and resolved findings never gate exit code on
// their own.
func (m *diffModel) overviewHeadline(width int) string {
	stats := m.computeOverviewStats()
	v := m.auditVerdict()
	parts := make([]string, 0, 4)
	if stats.changedTotal == 0 {
		parts = append(parts, render.Style("✓ No changes detected", render.Green, render.Bold))
	} else {
		parts = append(parts, render.Style(fmt.Sprintf("Δ %d package changes", stats.changedTotal), render.Yellow, render.Bold))
	}
	vulnIntroduced := 0
	if m.payload.Audit != nil {
		for _, f := range m.payload.Audit.Introduced {
			if isVulnerabilityFinding(f) {
				vulnIntroduced++
			}
		}
	}
	if vulnIntroduced == 0 {
		parts = append(parts, render.Style("✓ No new vulnerabilities", render.Green, render.Bold))
	} else {
		parts = append(parts, render.Style(fmt.Sprintf("✗ %d new vulnerabilities", vulnIntroduced), render.Red, render.Bold))
	}
	switch v.Verdict() {
	case "NOT EVALUATED":
		parts = append(parts, render.Style("◌ Audit not run", render.Dim, render.Bold))
	case "FAIL":
		parts = append(parts, render.Style(fmt.Sprintf("✗ Audit FAIL (%d new, exit 2)", v.FailingIntroduced), render.Red, render.Bold))
	case "PASS":
		if v.IntroducedTotal > 0 {
			// All introduced findings are warn-only.
			parts = append(parts, render.Style(fmt.Sprintf("⚠ Audit PASS (%d warn-only, exit 0)", v.IntroducedTotal), render.Yellow, render.Bold))
		} else {
			parts = append(parts, render.Style("✓ Audit PASS (exit 0)", render.Green, render.Bold))
		}
	}
	if stats.matchedFuzzy > 0 {
		parts = append(parts, render.Style(fmt.Sprintf("≈ %d fuzzy-reconciled", stats.matchedFuzzy), render.Cyan, render.Bold))
	}
	sep := render.Style("  •  ", render.Dim)
	return truncateToWidth(strings.Join(parts, sep), width)
}

func (m *diffModel) overviewDashboardView(width, height int) string {
	if width < 80 || height < 22 {
		return m.shellModel.View(width, height) //nolint:staticcheck // explicit selector bypasses the View shadow on the embedding model
	}
	var lines []string
	for _, line := range m.shellSummaryLines() {
		lines = append(lines, truncateToWidth(line, width))
	}
	// Headline row + spacer.
	lines = append(lines, m.overviewHeadline(width), "")
	footerLines := m.diffFooterLines(width)
	bodyHeight := height - len(lines) - len(footerLines)
	if bodyHeight < 14 {
		return m.shellModel.View(width, height) //nolint:staticcheck // explicit selector bypasses the View shadow on the embedding model
	}

	stats := m.computeOverviewStats()
	s := m.payload.Summary
	cardHeight := 9
	gap := 1
	cardWidth := (width - 4*gap) / 5
	// Five equal cards on the top row: Manifests / Packages /
	// Vulnerabilities / Licenses / Findings. The 5th "Findings" card
	// summarizes audit findings broken out by FindingKind so the user
	// has a single read of "what kinds of policy problems are in play"
	// before drilling into the per-kind tables below.
	findingsTotal := stats.findingsByKind["vulnerability"] +
		stats.findingsByKind["license"] +
		stats.findingsByKind["package"] +
		stats.findingsByKind["other"]
	cards := [][]string{
		boxView("Manifests", summaryCountCardLines(s.AddedManifestCount+s.ChangedManifestCount+s.RemovedManifestCount, "Changed Manifests", cardWidth-2, render.Cyan,
			render.Style(fmt.Sprintf("%d added", s.AddedManifestCount), render.Green),
			render.Style(fmt.Sprintf("%d changed", s.ChangedManifestCount), render.Yellow),
			render.Style(fmt.Sprintf("%d removed", s.RemovedManifestCount), render.Red),
		), cardWidth, cardHeight, render.Cyan),
		boxView("Packages", summaryCountCardLines(s.AddedPackageCount+s.ChangedPackageCount+s.RemovedPackageCount, "Package Changes", cardWidth-2, render.Magenta,
			render.Style(fmt.Sprintf("%d added", s.AddedPackageCount), render.Green),
			render.Style(fmt.Sprintf("%d changed", s.ChangedPackageCount), render.Yellow),
			render.Style(fmt.Sprintf("%d removed", s.RemovedPackageCount), render.Red),
		), cardWidth, cardHeight, render.Magenta),
		boxView("Vulnerabilities", summaryCountCardLines(diffVulnTotal(m.payload), "Vuln Deltas", cardWidth-2, render.Red,
			render.Style(fmt.Sprintf("%d new", diffVulnCount(m.payload, "introduced")), render.Red),
			render.Style(fmt.Sprintf("%d old", diffVulnCount(m.payload, "persisted")), render.Yellow),
			render.Style(fmt.Sprintf("%d fixed", diffVulnCount(m.payload, "resolved")), render.Green),
		), cardWidth, cardHeight, render.Red),
		boxView("Licenses", summaryCountCardLines(len(stats.licenseUniqueIDs), "Unique Licenses", cardWidth-2, render.Yellow,
			render.Style(fmt.Sprintf("%d introduced events", stats.licenseDeltas["introduced"]), render.Green),
			render.Style(fmt.Sprintf("%d retired events", stats.licenseDeltas["retired"]), render.Red),
		), cardWidth, cardHeight, render.Yellow),
		boxView("Findings", summaryCountCardLines(findingsTotal, "Findings by Kind", cardWidth-2, render.Magenta,
			render.Style(fmt.Sprintf("%d vulnerability", stats.findingsByKind["vulnerability"]), render.Red),
			render.Style(fmt.Sprintf("%d license", stats.findingsByKind["license"]), render.Yellow),
			render.Style(fmt.Sprintf("%d package", stats.findingsByKind["package"]), render.Cyan),
		), cardWidth, cardHeight, render.Magenta),
	}
	for idx := 0; idx < cardHeight; idx++ {
		row := cards[0][idx]
		for c := 1; c < len(cards); c++ {
			row += " " + cards[c][idx]
		}
		lines = append(lines, row)
	}
	lines = append(lines, "")

	remaining := bodyHeight - cardHeight - 1
	leftWidth := width / 2
	rightWidth := width - leftWidth - 1
	leftA := remaining / 3
	if leftA < 6 && remaining >= 18 {
		leftA = 6
	}
	leftB := (remaining - leftA - 2) / 2
	leftC := remaining - leftA - leftB - 2
	if leftC < 4 {
		leftC = 4
	}
	leftContent := stackBoxes(
		boxView("Changes per Ecosystem", coloredDistributionLines(stats.ecosystems, stats.changedTotal, 8, leftWidth-2), leftWidth, leftA, render.Cyan),
		boxView("Changes per Relationship", coloredDistributionLines(stats.relationships, sumCounts(stats.relationships), 6, leftWidth-2), leftWidth, leftB, render.Cyan),
		boxView("Changes per Scope", coloredDistributionLines(stats.scopes, sumCounts(stats.scopes), 6, leftWidth-2), leftWidth, leftC, render.Green),
	)
	rightA := remaining / 3
	if rightA < 6 && remaining >= 18 {
		rightA = 6
	}
	rightB := (remaining - rightA - 2) / 2
	rightC := remaining - rightA - rightB - 2
	if rightC < 4 {
		rightC = 4
	}
	rightContent := stackBoxes(
		boxView("Vulnerability Findings", findingsTableLines("Severity", severityRowKeys(), stats.vulnByStatus, severityRowColor, rightWidth-2), rightWidth, rightA, render.Red),
		boxView("License Findings", findingsTableLines("Rule", licenseRuleRowKeys(), stats.licenseByStatus, ruleRowColor, rightWidth-2), rightWidth, rightB, render.Yellow),
		boxView("Package Findings", findingsTableLines("Rule", packageRuleRowKeys(), stats.packageByStatus, ruleRowColor, rightWidth-2), rightWidth, rightC, render.Cyan),
	)
	lines = append(lines, joinColumns(leftContent, rightContent, leftWidth, rightWidth)...)
	lines = append(lines, footerLines...)
	return strings.Join(lines, "\n")
}

// diffFooterLines mirrors scan's scanFooterLines for use by the dashboard.
func (m *diffModel) diffFooterLines(width int) []string {
	return []string{
		statusBar(m.diffFooterSummary(), width),
		centerLine(m.diffLegend(), width),
	}
}

// sumCounts returns the total of all values in a map[string]int.
func sumCounts(counts map[string]int) int {
	n := 0
	for _, v := range counts {
		n += v
	}
	return n
}

// findingsTableLines renders a 4-column table (label / introduced /
// persisted / resolved) for the per-kind finding panes on the Overview
// tab. The first column header (label) is passed in by the caller so the
// same renderer powers severity tables and rule tables.
//
// Rows always appear in `rows` order, even when every cell is zero — a
// stable layout makes it easier to scan multiple diffs.
func findingsTableLines(label string, rows []string, table map[string]map[string]int, rowColor func(row string) string, width int) []string {
	const (
		introCol = "introduced"
		persCol  = "persisted"
		resvCol  = "resolved"
	)
	// Column headers use the short audit-status labels (New/Old/Fixed)
	// so the table reads consistently with everything else on the tab.
	header := render.Style(
		padRight(label, findingsTableLabelWidth(width))+
			padRight("New", 6)+
			padRight("Old", 6)+
			padRight("Fixed", 7),
		render.Dim,
	)
	out := []string{header}
	totalIntro, totalPers, totalResv := 0, 0, 0
	for _, row := range rows {
		cells := table[row]
		intro, pers, resv := cells[introCol], cells[persCol], cells[resvCol]
		totalIntro += intro
		totalPers += pers
		totalResv += resv
		color := render.Dim
		if rowColor != nil {
			color = rowColor(row)
			if color == "" {
				color = render.Dim
			}
		}
		// Dim 0-rows entirely so the eye lands on populated rows; bold any
		// nonzero figure so introduced/persisted/resolved differences pop.
		if intro+pers+resv == 0 {
			color = render.Dim
		}
		labelStyled := render.Style(padRight(titleCase(row), findingsTableLabelWidth(width)), color, render.Bold)
		out = append(out, labelStyled+
			styledCell(intro, 6, render.Red)+
			styledCell(pers, 6, render.Yellow)+
			styledCell(resv, 7, render.Green))
	}
	// Footer total row helps the reader gut-check against the per-kind
	// total shown in the Findings card.
	out = append(out, render.Style(
		padRight("Total", findingsTableLabelWidth(width)),
		render.White, render.Bold,
	)+
		styledCell(totalIntro, 6, render.White)+
		styledCell(totalPers, 6, render.White)+
		styledCell(totalResv, 7, render.White))
	return out
}

// findingsTableLabelWidth picks a sensible label-column width given the
// pane's available width. Reserves room for the New/Old/Fixed numeric
// columns (6+6+7 = 19 cells); everything else goes to the label.
func findingsTableLabelWidth(width int) int {
	w := width - 19
	if w < 8 {
		return 8
	}
	if w > 22 {
		return 22
	}
	return w
}

// styledCell renders a numeric cell of fixed width. Zero is dimmed so
// the eye skips it; nonzero values get the supplied color.
func styledCell(n, colWidth int, color string) string {
	text := fmt.Sprintf("%d", n)
	if n == 0 {
		return render.Style(padRight(text, colWidth), render.Dim)
	}
	return render.Style(padRight(text, colWidth), color, render.Bold)
}

// severityRowColor maps a severity row name to its display color so the
// table can lean on the existing severityColorCode helper.
func severityRowColor(row string) string {
	return severityColorCode(row)
}

// ruleRowColor returns a neutral color for license/package rule rows —
// the rule name itself isn't intrinsically red or green. We use a single
// Cyan for non-"other" rows and Dim for the "other" catch-all.
func ruleRowColor(row string) string {
	if row == "other" {
		return render.Dim
	}
	return render.Cyan
}

// diffVulnTotal returns the total count of vuln-kind deltas across all
// audit-status buckets (Introduced+Persisted+Resolved).
func diffVulnTotal(p output.DiffResponse) int {
	if p.Audit == nil {
		return 0
	}
	n := 0
	for _, group := range [][]output.AuditFinding{p.Audit.Introduced, p.Audit.Persisted, p.Audit.Resolved} {
		for _, f := range group {
			if isVulnerabilityFinding(f) {
				n++
			}
		}
	}
	return n
}

func diffVulnCount(p output.DiffResponse, status string) int {
	if p.Audit == nil {
		return 0
	}
	var bucket []output.AuditFinding
	switch status {
	case "introduced":
		bucket = p.Audit.Introduced
	case "persisted":
		bucket = p.Audit.Persisted
	case "resolved":
		bucket = p.Audit.Resolved
	}
	n := 0
	for _, f := range bucket {
		if isVulnerabilityFinding(f) {
			n++
		}
	}
	return n
}

func (m *diffModel) overviewPanels() []listPanel {
	summary := m.payload.Summary
	panels := []listPanel{
		{title: "Manifests", lines: []string{
			render.Style(fmt.Sprintf("%d Added", summary.AddedManifestCount), render.Green, render.Bold),
			render.Style(fmt.Sprintf("%d Changed", summary.ChangedManifestCount), render.Yellow, render.Bold),
			render.Style(fmt.Sprintf("%d Removed", summary.RemovedManifestCount), render.Red, render.Bold),
			render.Style(fmt.Sprintf("%d Unchanged", summary.UnchangedManifestCount), render.Cyan, render.Bold),
		}, color: render.Cyan, weight: 1},
		{title: "Packages", lines: []string{
			render.Style(fmt.Sprintf("%d Added", summary.AddedPackageCount), render.Green, render.Bold),
			render.Style(fmt.Sprintf("%d Changed", summary.ChangedPackageCount), render.Yellow, render.Bold),
			render.Style(fmt.Sprintf("%d Removed", summary.RemovedPackageCount), render.Red, render.Bold),
		}, color: render.Magenta, weight: 1},
	}
	if m.payload.Audit != nil {
		panels = append(panels, listPanel{
			title: "Vulnerabilities",
			lines: []string{
				render.Style(fmt.Sprintf("%d New", len(m.payload.Audit.Introduced)), render.Red, render.Bold),
				render.Style(fmt.Sprintf("%d Old", len(m.payload.Audit.Persisted)), render.Yellow, render.Bold),
				render.Style(fmt.Sprintf("%d Fixed", len(m.payload.Audit.Resolved)), render.Green, render.Bold),
			},
			color:  render.Red,
			weight: 1,
		})
	}
	return panels
}

func (m *diffModel) overviewAuditDetails() []string {
	audit := m.payload.Audit
	if audit == nil {
		return []string{render.Style("Audit data not available. Run with --enrich --audit.", render.Dim)}
	}
	return []string{
		render.Style("Vulnerability Deltas", render.Bold, render.Red),
		"",
		render.Style("  New: ", render.Dim) + render.Style(fmt.Sprintf("%d", len(audit.Introduced)), render.Red, render.Bold),
		render.Style("  Old: ", render.Dim) + render.Style(fmt.Sprintf("%d", len(audit.Persisted)), render.Yellow, render.Bold),
		render.Style("  Fixed: ", render.Dim) + render.Style(fmt.Sprintf("%d", len(audit.Resolved)), render.Green, render.Bold),
	}
}

func (m *diffModel) overviewAuditSummaryDetails() []string {
	audit := m.payload.Audit
	if audit == nil || audit.AuditSummary == nil {
		return []string{render.Style("Severity histogram not available.", render.Dim)}
	}
	s := audit.AuditSummary
	return []string{
		render.Style("Severity Histogram", render.Bold, render.Red),
		"",
		render.Style("  Critical: ", render.Dim) + fmt.Sprintf("%d", s.Critical),
		render.Style("  High: ", render.Dim) + fmt.Sprintf("%d", s.High),
		render.Style("  Medium: ", render.Dim) + fmt.Sprintf("%d", s.Medium),
		render.Style("  Low: ", render.Dim) + fmt.Sprintf("%d", s.Low),
		render.Style("  Unknown: ", render.Dim) + fmt.Sprintf("%d", s.Unknown),
		render.Style("  Total: ", render.Dim) + render.Style(fmt.Sprintf("%d", s.Total), render.White, render.Bold),
	}
}

func (m *diffModel) overviewTopChangedManifests() []string {
	type ranked struct {
		name  string
		count int
	}
	rows := make([]ranked, 0, len(m.payload.Results.Manifests))
	for _, mf := range m.payload.Results.Manifests {
		rows = append(rows, ranked{
			name:  render.DiffManifestDisplayLabel(mf),
			count: len(mf.Added) + len(mf.Changed) + len(mf.Removed),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].count > rows[j].count })
	lines := []string{render.Style("Top Changed Manifests", render.Bold, render.Cyan), ""}
	limit := 10
	if len(rows) < limit {
		limit = len(rows)
	}
	for i := 0; i < limit; i++ {
		if rows[i].count == 0 {
			continue
		}
		lines = append(lines, render.Style("  "+rows[i].name+": ", render.Dim)+fmt.Sprintf("%d changes", rows[i].count))
	}
	if len(lines) == 2 {
		lines = append(lines, render.Style("  (no changes)", render.Dim))
	}
	return lines
}

// --- Components tab -------------------------------------------------------

// flatComponentChange is one Added/Changed/Removed package, lifted out of
// its manifest into a flat list so the Components tab can group it freely
// (by status, manifest, or ecosystem) and filter by scope/relationship/severity.
type flatComponentChange struct {
	manifest     output.DiffManifestResult
	manifestKey  string
	manifestName string
	ecosystem    string
	status       string // "added" / "changed" / "removed"
	pkgName      string
	pkgRef       output.PackageRef // After for changed, Package for added/removed
	beforePkg    output.PackageRef // populated for changed entries
	beforeVer    string
	afterVer     string
	maxSeverity  string // worst severity across pkgRef.Vulnerabilities
	relationship string // root/direct/transitive — looked up in head/base graph
}

func (m *diffModel) collectComponentChanges() []flatComponentChange {
	headRels := map[string]string{}
	if g, _ := graphFromConsolidated(m.headGraph); g != nil {
		headRels = classifyRelationships(g)
	}
	baseRels := map[string]string{}
	if g, _ := graphFromConsolidated(m.baseGraph); g != nil {
		baseRels = classifyRelationships(g)
	}
	// pickRel prefers the graph where the package actually exists. Removed
	// packages live in BASE; added/changed live in HEAD. Fall through to
	// the other graph if the primary lookup misses (e.g. fuzzy-changed
	// packages whose ID differs between sides).
	pickRel := func(status, pkgID string) string {
		primary := headRels
		fallback := baseRels
		if status == "removed" {
			primary, fallback = baseRels, headRels
		}
		if r := primary[pkgID]; r != "" {
			return r
		}
		if r := fallback[pkgID]; r != "" {
			return r
		}
		return ""
	}
	out := make([]flatComponentChange, 0)
	for _, mf := range m.payload.Results.Manifests {
		mfKey := diffManifestKey(mf)
		mfName := render.DiffManifestDisplayLabel(mf)
		eco := valueOrDefault(mf.Ecosystem, "unknown")
		for _, change := range mf.Added {
			out = append(out, flatComponentChange{
				manifest: mf, manifestKey: mfKey, manifestName: mfName, ecosystem: eco,
				status: "added", pkgName: render.DiffPackageDisplayName(change.Package),
				pkgRef: change.Package, maxSeverity: maxSeverity(change.Package.Vulnerabilities),
				relationship: pickRel("added", change.Package.ID),
			})
		}
		for _, change := range mf.Changed {
			out = append(out, flatComponentChange{
				manifest: mf, manifestKey: mfKey, manifestName: mfName, ecosystem: eco,
				status: "changed", pkgName: render.DiffPackageDisplayName(change.After),
				pkgRef: change.After, beforePkg: change.Before,
				beforeVer: change.Before.Version, afterVer: change.After.Version,
				maxSeverity:  maxSeverity(change.After.Vulnerabilities),
				relationship: pickRel("changed", change.After.ID),
			})
		}
		for _, change := range mf.Removed {
			out = append(out, flatComponentChange{
				manifest: mf, manifestKey: mfKey, manifestName: mfName, ecosystem: eco,
				status: "removed", pkgName: render.DiffPackageDisplayName(change.Package),
				pkgRef: change.Package, maxSeverity: maxSeverity(change.Package.Vulnerabilities),
				relationship: pickRel("removed", change.Package.ID),
			})
		}
	}
	return out
}

func relationshipFromMap(rels map[string]string, id string) string {
	if r, ok := rels[id]; ok {
		return r
	}
	return ""
}

func maxSeverity(vulns []output.VulnerabilityRef) string {
	best := ""
	bestRank := severityRank("zzz")
	for _, v := range vulns {
		sev := strings.ToLower(strings.TrimSpace(v.Severity))
		if sev == "" {
			sev = "unknown"
		}
		if r := severityRank(sev); r < bestRank {
			bestRank = r
			best = sev
		}
	}
	return best
}

func (m *diffModel) buildComponentsTab() *listModel {
	all := m.collectComponentChanges()

	// Apply filters.
	filtered := make([]flatComponentChange, 0, len(all))
	for _, c := range all {
		if m.componentsRelationship != "" && c.relationship != m.componentsRelationship {
			continue
		}
		if m.componentsScope != "" {
			scope := strings.ToLower(strings.TrimSpace(c.pkgRef.Scope))
			if scope == "" {
				scope = "unset"
			}
			if scope != m.componentsScope {
				continue
			}
		}
		if m.componentsSeverity != "" && !strings.EqualFold(c.maxSeverity, m.componentsSeverity) {
			continue
		}
		if m.componentsEcosystem != "" && !strings.EqualFold(c.ecosystem, m.componentsEcosystem) {
			continue
		}
		filtered = append(filtered, c)
	}

	group := m.componentsGroup
	if group == "" {
		group = componentsGroupStatus
	}

	// Bucket by current group key.
	groups := make(map[string][]flatComponentChange)
	for _, c := range filtered {
		groups[componentsGroupKey(c, group)] = append(groups[componentsGroupKey(c, group)], c)
	}
	keys := sortedComponentsGroupKeys(groups, group)

	items := make([]listItem, 0)
	for _, key := range keys {
		groupItems := groups[key]
		gKey := string(group) + ":" + key
		isExpanded := expandedValue(m.componentsExpanded, gKey, true)
		items = append(items, listItem{
			title:    fmt.Sprintf("%s (%d)", componentsGroupLabel(key, group), len(groupItems)),
			subtitle: string(group),
			details:  m.componentsGroupDetails(key, group, groupItems),
			key:      gKey,
			canOpen:  len(groupItems) > 0,
			expanded: isExpanded,
		})
		if !isExpanded {
			continue
		}
		for _, c := range groupItems {
			items = append(items, listItem{
				title:    componentChangeRowTitle(c),
				subtitle: c.status,
				badges:   componentChangeBadges(c),
				details:  componentChangeDetails(c),
				depth:    1,
				tree:     "  ",
			})
		}
	}

	added, changed, removed := 0, 0, 0
	for _, c := range filtered {
		switch c.status {
		case "added":
			added++
		case "changed":
			changed++
		case "removed":
			removed++
		}
	}

	controls := []string{
		keyHint("/", "search") + " " + keyHint("g", "group") + " " + keyHint("r", "relationship") + " " + keyHint("s", "scope") + " " + keyHint("v", "severity") + " " + keyHint("e", "ecosystem") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all"),
		render.Style("Group: ", render.Dim) + render.Style(componentsGroupName(group), render.BgYellow, render.Bold) +
			render.Style(" | Relationship: ", render.Dim) + render.Style(valueOrDefault(m.componentsRelationship, "All"), render.BgYellow, render.Bold) +
			render.Style(" | Scope: ", render.Dim) + render.Style(valueOrDefault(m.componentsScope, "All"), render.BgYellow, render.Bold) +
			render.Style(" | Severity: ", render.Dim) + render.Style(valueOrDefault(m.componentsSeverity, "All"), render.BgYellow, render.Bold) +
			render.Style(" | Ecosystem: ", render.Dim) + render.Style(valueOrDefault(m.componentsEcosystem, "All"), render.BgYellow, render.Bold) +
			render.Style(" | Added: ", render.Dim) + render.Style(fmt.Sprintf("%d", added), render.Green, render.Bold) +
			render.Style(" | Changed: ", render.Dim) + render.Style(fmt.Sprintf("%d", changed), render.Yellow, render.Bold) +
			render.Style(" | Removed: ", render.Dim) + render.Style(fmt.Sprintf("%d", removed), render.Red, render.Bold),
	}

	return &listModel{
		controls:       controls,
		listTitle:      fmt.Sprintf("Components (%d)", len(filtered)),
		detailTitle:    "Component Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; g cycles group; r/s/v cycle relationship/scope/severity; → expands; Enter focuses details; 1-7 switch tabs",
		emptyState:     "No package changes match the current filters.",
		items:          items,
	}
}

func componentsGroupKey(c flatComponentChange, group componentsGroup) string {
	switch group {
	case componentsGroupManifest:
		if c.manifestName == "" {
			return "(unknown manifest)"
		}
		return c.manifestName
	case componentsGroupEcosystem:
		return c.ecosystem
	default:
		return c.status
	}
}

func componentsGroupLabel(key string, group componentsGroup) string {
	switch group {
	case componentsGroupStatus:
		return titleCase(key)
	default:
		return key
	}
}

func componentsGroupName(group componentsGroup) string {
	switch group {
	case componentsGroupManifest:
		return "Manifest"
	case componentsGroupEcosystem:
		return "Ecosystem"
	default:
		return "Status"
	}
}

func sortedComponentsGroupKeys(groups map[string][]flatComponentChange, group componentsGroup) []string {
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if group == componentsGroupStatus {
			order := map[string]int{"added": 0, "changed": 1, "removed": 2}
			return order[keys[i]] < order[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

func (m *diffModel) componentsGroupDetails(key string, group componentsGroup, items []flatComponentChange) []string {
	lines := []string{
		render.Style(componentsGroupLabel(key, group), render.Bold, render.Cyan),
		"",
		render.Style("  Group axis: ", render.Dim) + componentsGroupName(group),
		render.Style("  Items: ", render.Dim) + fmt.Sprintf("%d", len(items)),
	}
	counts := map[string]int{"added": 0, "changed": 0, "removed": 0}
	for _, c := range items {
		counts[c.status]++
	}
	lines = append(lines,
		render.Style("  Added: ", render.Dim)+fmt.Sprintf("%d", counts["added"]),
		render.Style("  Changed: ", render.Dim)+fmt.Sprintf("%d", counts["changed"]),
		render.Style("  Removed: ", render.Dim)+fmt.Sprintf("%d", counts["removed"]),
	)
	// When grouping by manifest, surface the manifest's full metadata
	// (ecosystem, package manager, detector, subproject path) so the user
	// knows exactly what this row represents.
	if group == componentsGroupManifest && len(items) > 0 {
		mf := items[0].manifest
		lines = append(lines,
			"",
			render.Style("Manifest", render.Bold, render.Magenta),
			render.Style("  Path: ", render.Dim)+valueOrDash(mf.Path),
			render.Style("  Kind: ", render.Dim)+valueOrDash(mf.Kind),
			render.Style("  Subproject: ", render.Dim)+valueOrDash(mf.Subproject),
			render.Style("  Ecosystem: ", render.Dim)+valueOrDash(mf.Ecosystem),
			render.Style("  Package manager: ", render.Dim)+valueOrDash(mf.PackageManager),
			render.Style("  Detector: ", render.Dim)+valueOrDash(m.detectorForManifest(mf)),
			render.Style("  Status: ", render.Dim)+statusText(mf.Status),
		)
	}
	return lines
}

func componentChangeRowTitle(c flatComponentChange) string {
	if c.status == "changed" {
		return fmt.Sprintf("%s  (%s → %s)", c.pkgName, valueOrDash(c.beforeVer), valueOrDash(c.afterVer))
	}
	return c.pkgName
}

func componentChangeDetailTitle(c flatComponentChange) string {
	switch c.status {
	case "added":
		return "Added package"
	case "removed":
		return "Removed package"
	default:
		return "Changed package"
	}
}

func componentChangeBadges(c flatComponentChange) []badge {
	// The row's subtitle already renders a colored status badge for
	// added/changed/removed (see statusBadge). Adding the same word
	// again as a badge here showed it twice, which the user flagged.
	// Severity and relationship still get their own badges since they
	// carry orthogonal information.
	out := make([]badge, 0, 2)
	if c.maxSeverity != "" {
		out = append(out, badge{label: strings.ToUpper(c.maxSeverity), kind: "severity-" + c.maxSeverity})
	}
	if c.relationship != "" {
		out = append(out, badge{label: strings.ToUpper(c.relationship), kind: "relationship-" + c.relationship})
	}
	return out
}

// componentChangeDetails renders the right-pane details for one Component
// row. For changed packages it shows BEFORE/AFTER for version, scope,
// licenses, and vulnerabilities so the user can see exactly what shifted.
// For added/removed packages it shows the package's full inventory.
func (m *diffModel) detectorForManifest(mf output.DiffManifestResult) string {
	if det := lookupDetector(m.headGraph, mf); det != "" {
		return det
	}
	if det := lookupDetector(m.baseGraph, mf); det != "" {
		return det
	}
	return ""
}

func lookupDetector(consolidated sdk.ConsolidatedGraph, mf output.DiffManifestResult) string {
	for _, cm := range consolidated.Manifests {
		if cm.Entry.Manifest.Path == mf.Path && cm.Subproject.RelativePath == mf.Subproject {
			return cm.DetectorName
		}
	}
	// Fallback: match by path alone.
	for _, cm := range consolidated.Manifests {
		if cm.Entry.Manifest.Path == mf.Path {
			return cm.DetectorName
		}
	}
	return ""
}

func componentChangeDetails(c flatComponentChange) []string {
	title := componentChangeDetailTitle(c)
	lines := []string{
		render.Style(title, render.Bold, render.Cyan),
		render.Style("  "+c.pkgName, render.White, render.Bold),
		"",
		render.Style("Identity", render.Bold, render.Magenta),
		render.Style("  ID: ", render.Dim) + valueOrDash(c.pkgRef.ID),
		render.Style("  Purl: ", render.Dim) + valueOrDash(c.pkgRef.Purl),
		render.Style("  Scope: ", render.Dim) + valueOrDash(c.pkgRef.Scope),
		render.Style("  Relationship: ", render.Dim) + valueOrDash(c.relationship),
		render.Style("  Ecosystem: ", render.Dim) + valueOrDash(c.ecosystem),
		"",
		render.Style("Manifest", render.Bold, render.Magenta),
		render.Style("  Path: ", render.Dim) + valueOrDash(c.manifest.Path),
		render.Style("  Kind: ", render.Dim) + valueOrDash(c.manifest.Kind),
		render.Style("  Subproject: ", render.Dim) + valueOrDash(c.manifest.Subproject),
		render.Style("  Package manager: ", render.Dim) + valueOrDash(c.manifest.PackageManager),
		render.Style("  Manifest status: ", render.Dim) + statusText(c.manifest.Status),
	}

	if c.status == "changed" {
		lines = append(lines,
			"",
			render.Style("Version", render.Bold, render.Yellow),
			render.Style("  Before: ", render.Dim)+valueOrDash(c.beforeVer),
			render.Style("  After:  ", render.Dim)+valueOrDash(c.afterVer),
		)
		if c.beforePkg.Scope != c.pkgRef.Scope {
			lines = append(lines,
				"",
				render.Style("Scope changed", render.Bold, render.Yellow),
				render.Style("  Before: ", render.Dim)+valueOrDash(c.beforePkg.Scope),
				render.Style("  After:  ", render.Dim)+valueOrDash(c.pkgRef.Scope),
			)
		}
		lines = append(lines, renderLicenseDelta(c.beforePkg.Licenses, c.pkgRef.Licenses)...)
		lines = append(lines, renderVulnDelta(c.beforePkg.Vulnerabilities, c.pkgRef.Vulnerabilities)...)
	} else {
		lines = append(lines, renderLicenseList(c.pkgRef.Licenses)...)
		lines = append(lines, renderVulnList(c.pkgRef.Vulnerabilities)...)
	}
	return lines
}

// renderLicenseList renders one package's license inventory.
func renderLicenseList(licenses []output.LicenseRef) []string {
	out := []string{"", render.Style("Licenses", render.Bold, render.Yellow)}
	if len(licenses) == 0 {
		out = append(out, render.Style("  (none)", render.Dim))
		return out
	}
	for _, lic := range licenses {
		id := lic.Identifier()
		if id == "" {
			id = "(empty)"
		}
		line := render.Style("  - ", render.Dim) + id
		if lic.Type != "" {
			line += render.Style("  ["+lic.Type+"]", render.Dim)
		}
		out = append(out, line)
	}
	return out
}

// renderLicenseDelta shows before/after license sets for a changed package.
func renderLicenseDelta(before, after []output.LicenseRef) []string {
	beforeSet, afterSet := licenseIDSet(before), licenseIDSet(after)
	if len(beforeSet) == 0 && len(afterSet) == 0 {
		return nil
	}
	out := []string{"", render.Style("Licenses (before → after)", render.Bold, render.Yellow)}
	for id := range afterSet {
		switch {
		case beforeSet[id]:
			out = append(out, render.Style("  = ", render.Dim)+id+render.Style("  (unchanged)", render.Dim))
		default:
			out = append(out, render.Style("  + ", render.Green, render.Bold)+id+render.Style("  (new)", render.Dim))
		}
	}
	for id := range beforeSet {
		if !afterSet[id] {
			out = append(out, render.Style("  - ", render.Red, render.Bold)+id+render.Style("  (retired)", render.Dim))
		}
	}
	return out
}

func licenseIDSet(licenses []output.LicenseRef) map[string]bool {
	out := make(map[string]bool, len(licenses))
	for _, lic := range licenses {
		if id := lic.Identifier(); id != "" {
			out[id] = true
		}
	}
	return out
}

// renderVulnList renders one package's full vulnerability inventory.
func renderVulnList(vulns []output.VulnerabilityRef) []string {
	out := []string{"", render.Style("Vulnerabilities", render.Bold, render.Red)}
	if len(vulns) == 0 {
		out = append(out, render.Style("  (none)", render.Dim))
		return out
	}
	for _, v := range vulns {
		out = append(out, render.Style("  - ", render.Dim)+severityText(v.Severity)+" "+valueOrDash(v.ID))
		if v.FixedIn != "" {
			out = append(out, render.Style("      fixed in: ", render.Dim)+v.FixedIn)
		}
		if v.FixState != "" {
			out = append(out, render.Style("      fix state: ", render.Dim)+v.FixState)
		}
		if exploitability := exploitabilityLine(v.KEVExploited, v.KnownExploited, v.RiskScore); exploitability != "" {
			out = append(out, render.Style("      exploitability: ", render.Dim)+exploitability)
		}
	}
	return out
}

// renderVulnDelta shows before/after vulnerabilities for a changed package.
func renderVulnDelta(before, after []output.VulnerabilityRef) []string {
	beforeSet, afterSet := vulnIDSet(before), vulnIDSet(after)
	if len(beforeSet) == 0 && len(afterSet) == 0 {
		return nil
	}
	out := []string{"", render.Style("Vulnerabilities (before → after)", render.Bold, render.Red)}
	for id, v := range afterSet {
		switch {
		case beforeSet[id] != nil:
			out = append(out, render.Style("  = ", render.Dim)+severityText(v.Severity)+" "+id+render.Style("  (old)", render.Dim))
		default:
			out = append(out, render.Style("  + ", render.Red, render.Bold)+severityText(v.Severity)+" "+id+render.Style("  (new)", render.Dim))
		}
	}
	for id, v := range beforeSet {
		if afterSet[id] == nil {
			out = append(out, render.Style("  - ", render.Green, render.Bold)+severityText(v.Severity)+" "+id+render.Style("  (fixed)", render.Dim))
		}
	}
	return out
}

func vulnIDSet(vulns []output.VulnerabilityRef) map[string]*output.VulnerabilityRef {
	out := make(map[string]*output.VulnerabilityRef, len(vulns))
	for i := range vulns {
		v := &vulns[i]
		if v.ID == "" {
			continue
		}
		out[v.ID] = v
	}
	return out
}

func diffManifestKey(mf output.DiffManifestResult) string {
	return mf.Path + "|" + mf.Subproject + "|" + mf.PackageManager
}

func sortedDiffManifests(manifests []output.DiffManifestResult) []output.DiffManifestResult {
	sorted := append([]output.DiffManifestResult(nil), manifests...)
	sort.Slice(sorted, func(i, j int) bool {
		left := sorted[i]
		right := sorted[j]
		if left.Status != right.Status {
			return render.DiffManifestStatusOrder(left.Status) < render.DiffManifestStatusOrder(right.Status)
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.PackageManager != right.PackageManager {
			return left.PackageManager < right.PackageManager
		}
		return left.Subproject < right.Subproject
	})
	return sorted
}

func diffPackageDetails(title string, manifest output.DiffManifestResult, label, before, after string, pkg output.PackageRef) []string {
	lines := []string{
		render.Style(title, render.Bold, render.Cyan),
		"",
		render.Style("  Package: ", render.Dim) + valueOrDash(label),
		render.Style("  Manifest: ", render.Dim) + render.DiffManifestDisplayLabel(manifest),
		render.Style("  Status: ", render.Dim) + statusText(manifest.Status),
		render.Style("  Ecosystem: ", render.Dim) + valueOrDash(manifest.Ecosystem),
		render.Style("  Package manager: ", render.Dim) + valueOrDash(manifest.PackageManager),
	}
	if before != "" || after != "" {
		lines = append(lines,
			"",
			render.Style("Version Change", render.Bold, render.Magenta),
			"",
			render.Style("  Before: ", render.Dim)+valueOrDash(before),
			render.Style("  After: ", render.Dim)+valueOrDash(after),
		)
	}
	if len(pkg.Licenses) > 0 {
		lines = append(lines, "", render.Style("Licenses", render.Bold, render.Yellow), "")
		for _, lic := range pkg.Licenses {
			lines = append(lines, render.Style("  - ", render.Dim)+valueOrDash(lic.Identifier()))
		}
	}
	if len(pkg.Vulnerabilities) > 0 {
		lines = append(lines, "", render.Style("Vulnerabilities", render.Bold, render.Red), "")
		for _, v := range pkg.Vulnerabilities {
			lines = append(lines, render.Style("  - ", render.Dim)+severityText(v.Severity)+" "+valueOrDash(v.ID))
		}
	}
	return lines
}

func diffManifestDetails(manifest output.DiffManifestResult) []string {
	lines := []string{
		render.Style("Manifest", render.Bold, render.Cyan),
		render.Style("  Status: ", render.Dim) + statusText(manifest.Status),
		render.Style("  Path: ", render.Dim) + valueOrDash(manifest.Path),
		render.Style("  Kind: ", render.Dim) + valueOrDash(manifest.Kind),
		render.Style("  Subproject: ", render.Dim) + valueOrDash(manifest.Subproject),
		render.Style("  Ecosystem: ", render.Dim) + valueOrDash(manifest.Ecosystem),
		render.Style("  Package manager: ", render.Dim) + valueOrDash(manifest.PackageManager),
		"",
	}
	appendSection := func(title string, values []string) {
		lines = append(lines, render.Style(title, render.Bold, render.Magenta))
		if len(values) == 0 {
			lines = append(lines, render.Style("  (none)", render.Dim), "")
			return
		}
		for _, v := range values {
			lines = append(lines, render.Style("  - ", render.Dim)+v)
		}
		lines = append(lines, "")
	}
	added := make([]string, 0, len(manifest.Added))
	for _, change := range manifest.Added {
		added = append(added, render.DiffPackageDisplayName(change.Package))
	}
	changed := make([]string, 0, len(manifest.Changed))
	for _, change := range manifest.Changed {
		changed = append(changed, fmt.Sprintf("%s (%s -> %s)", render.DiffPackageDisplayName(change.After), valueOrDash(change.Before.Version), valueOrDash(change.After.Version)))
	}
	removed := make([]string, 0, len(manifest.Removed))
	for _, change := range manifest.Removed {
		removed = append(removed, render.DiffPackageDisplayName(change.Package))
	}
	appendSection("Added packages", added)
	appendSection("Changed packages", changed)
	appendSection("Removed packages", removed)
	return lines
}

// --- Vulnerabilities / Findings tab ---------------------------------------

type auditDelta struct {
	status   string // "introduced", "persisted", "resolved"
	finding  output.AuditFinding
	severity string
}

// auditDeltas walks the three diff buckets and returns the subset
// matching `keep`. A nil predicate keeps every finding — used by the
// Findings tab which spans every FindingKind. The Vulnerabilities tab
// passes isVulnerabilityFinding.
func (m *diffModel) auditDeltas(keep func(output.AuditFinding) bool) []auditDelta {
	out := make([]auditDelta, 0)
	if m.payload.Audit == nil {
		return out
	}
	collect := func(status string, findings []output.AuditFinding) {
		for _, f := range findings {
			if keep != nil && !keep(f) {
				continue
			}
			out = append(out, auditDelta{status: status, finding: f, severity: f.Severity})
		}
	}
	collect("introduced", m.payload.Audit.Introduced)
	collect("persisted", m.payload.Audit.Persisted)
	collect("resolved", m.payload.Audit.Resolved)
	return out
}

func isVulnerabilityFinding(f output.AuditFinding) bool {
	// Prefer the explicit Auditor name when present — it's what the diff
	// engine sets and is the most reliable signal.
	switch strings.ToLower(strings.TrimSpace(f.Auditor)) {
	case "vulnerability":
		return true
	case "license", "package":
		return false
	}
	kind := strings.ToLower(strings.TrimSpace(f.Kind))
	if kind == "" {
		// Fallback: presence of a CVE/GHSA-shaped ID or a Source like
		// "osv"/"grype" implies a vulnerability finding.
		source := strings.ToLower(f.Source)
		if strings.HasPrefix(strings.ToUpper(f.ID), "CVE-") || strings.HasPrefix(strings.ToUpper(f.ID), "GHSA-") {
			return true
		}
		return source == "osv" || source == "grype" || strings.Contains(source, "vuln")
	}
	return kind == "vulnerability" || kind == "vuln" || kind == "advisory" || kind == "cve"
}

// nextVulnGroup cycles the grouping axis for the Vulnerabilities tab.
// Severity makes sense here because every vuln finding carries one.
func nextVulnGroup(group string) string {
	switch group {
	case "status":
		return "severity"
	case "severity":
		return "package"
	default:
		return "status"
	}
}

// nextFindingGroup cycles the grouping axis for the Findings tab.
// Severity is intentionally absent — license and package auditors emit
// `Severity = "unknown"` for everything, so grouping by it is degenerate.
// "kind" (auditor name) replaces severity since it's the most useful
// secondary axis for non-vuln findings.
func nextFindingGroup(group string) string {
	switch group {
	case "status":
		return "kind"
	case "kind":
		return "package"
	default:
		return "status"
	}
}

func (m *diffModel) buildVulnsTab() *listModel {
	list := m.buildAuditTab(auditTabConfig{
		keep:       isVulnerabilityFinding,
		group:      m.vulnGroup,
		groupHints: "status/severity/package",
		expanded:   m.vulnExpanded,
		listLabel:  "Vulnerabilities",
		itemNoun:   "vulnerability",
	})
	list.topPanels = append(m.vulnsOutcomePanels(), list.topPanels...)
	return list
}

func (m *diffModel) buildFindingsTab() *listModel {
	// The Findings tab spans EVERY FindingKind — no kind filter. The
	// "kind" group axis below uses AuditFinding.Kind so users can split
	// the list by vulnerability / license / package / (other).
	list := m.buildAuditTab(auditTabConfig{
		keep:       nil,
		group:      m.findingGroup,
		groupHints: "status/kind/package",
		expanded:   m.findingExpanded,
		listLabel:  "Findings",
		itemNoun:   "finding",
	})
	list.topPanels = append(m.findingsOutcomePanels(), list.topPanels...)
	return list
}

// auditTabConfig collects everything buildAuditTab needs.
type auditTabConfig struct {
	keep       func(output.AuditFinding) bool // nil keeps every finding
	group      string
	groupHints string // shown after "g cycles group "
	expanded   map[string]bool
	listLabel  string // e.g. "Vulnerabilities" / "Findings"
	itemNoun   string // e.g. "vulnerability" / "finding"
}

// auditVerdict captures the diff command's audit outcome, mirroring
// `internal/cli/diff_cmd.go:161-165`:
//
//	if audit didn't run                                                → NotEvaluated
//	if audit ran AND no INTRODUCED finding has a failing Disposition   → Pass
//	if audit ran AND at least one INTRODUCED finding fails policy      → Fail (exit 2)
//
// A finding "fails policy" when its Disposition is either empty (the
// auditor didn't set one — historical default = fail) or "fail". See
// internal/output/types.go::FailingFindingCount. Only the *Introduced*
// bucket gates the exit code, so resolving or persisting findings does
// NOT trip the FAIL exit on its own.
type auditVerdict struct {
	Ran                      bool
	Total                    int // AuditSummary.Total (Introduced+Persisted with current scan_output.go)
	FailingIntroduced        int // count of introduced findings with Disposition ∈ {"", "fail"} — gates run-level exit code
	FailingIntroducedVuln    int // subset of FailingIntroduced whose finding is vuln-kind
	FailingIntroducedNonVuln int // subset of FailingIntroduced whose finding is NOT vuln-kind (lives in Findings tab)
	WarnIntroduced           int // count of introduced findings with Disposition == "warn"
	IntroducedTotal          int
	PersistedTotal           int
	ResolvedTotal            int
	IntroducedVuln           int
	PersistedVuln            int
	ResolvedVuln             int
	IntroducedNonVuln        int
	PersistedNonVuln         int
	ResolvedNonVuln          int
	HasNonVulnFindings       bool // true when at least one finding has Kind != vulnerability
}

// auditFindingFails mirrors output.FailingFindingCount's gate but operates
// on the output.AuditFinding type that the TUI consumes. Keeping this
// helper alongside the verdict struct makes the mapping explicit.
func auditFindingFails(f output.AuditFinding) bool {
	switch f.Disposition {
	case "", string(sdk.FindingDispositionFail):
		return true
	default:
		return false
	}
}

func (m *diffModel) auditVerdict() auditVerdict {
	v := auditVerdict{}
	if m.payload.Audit == nil {
		return v
	}
	v.Ran = true
	if m.payload.Audit.AuditSummary != nil {
		v.Total = m.payload.Audit.AuditSummary.Total
	}
	classify := func(bucket []output.AuditFinding) (total, vuln, nonVuln int) {
		for _, f := range bucket {
			total++
			if isVulnerabilityFinding(f) {
				vuln++
			} else {
				nonVuln++
				v.HasNonVulnFindings = true
			}
		}
		return
	}
	v.IntroducedTotal, v.IntroducedVuln, v.IntroducedNonVuln = classify(m.payload.Audit.Introduced)
	v.PersistedTotal, v.PersistedVuln, v.PersistedNonVuln = classify(m.payload.Audit.Persisted)
	v.ResolvedTotal, v.ResolvedVuln, v.ResolvedNonVuln = classify(m.payload.Audit.Resolved)
	// Disposition gate runs on Introduced ONLY — same as diff_cmd.go:161-165.
	// We also split the failing count by vuln vs non-vuln so each tab
	// (Vulnerabilities / Findings) can render an outcome panel that
	// stays consistent with the rows it's actually showing.
	for _, f := range m.payload.Audit.Introduced {
		switch f.Disposition {
		case "", string(sdk.FindingDispositionFail):
			v.FailingIntroduced++
			if isVulnerabilityFinding(f) {
				v.FailingIntroducedVuln++
			} else {
				v.FailingIntroducedNonVuln++
			}
		case string(sdk.FindingDispositionWarn):
			v.WarnIntroduced++
		}
	}
	return v
}

// Verdict returns PASS / FAIL / NOT EVALUATED for the diff command's exit
// code, matching diff_cmd.go:161-165.
func (v auditVerdict) Verdict() string {
	switch {
	case !v.Ran:
		return "NOT EVALUATED"
	case v.FailingIntroduced > 0:
		return "FAIL"
	default:
		return "PASS"
	}
}

// findingsOutcomePanels renders the audit-outcome summary at the top of
// the Findings tab.
func (m *diffModel) findingsOutcomePanels() []listPanel {
	v := m.auditVerdict()
	if !v.Ran {
		return []listPanel{{
			title: "Audit Outcome",
			lines: []string{
				render.Style(" NOT EVALUATED ", render.BgYellow, render.Black, render.Bold),
				"",
				render.Style("Audit was not run.", render.Dim),
				render.Style("Re-run with --enrich --audit", render.Dim),
				render.Style("to evaluate policy.", render.Dim),
			},
			color:  render.Yellow,
			weight: 2,
		}}
	}

	// The Findings tab spans every FindingKind, so the outcome panel
	// matches the run-level verdict exactly — no "(this tab)" qualifier
	// is needed. The breakdown beneath it shows ALL findings, split by
	// kind so the user can see which auditor produced what.
	var verdictBadge, verdictExplain, verdictNote, verdictColor string
	switch {
	case v.FailingIntroduced > 0:
		verdictBadge = render.Style(" FAIL ", render.BgRed, render.White, render.Bold)
		verdictExplain = fmt.Sprintf("%d new finding(s) gate exit code", v.FailingIntroduced)
		verdictNote = fmt.Sprintf("Exit code 2 (%d vuln + %d license/package)",
			v.FailingIntroducedVuln, v.FailingIntroducedNonVuln)
		verdictColor = render.Red
	case v.IntroducedTotal > 0:
		verdictBadge = render.Style(" PASS (warn-only) ", render.BgYellow, render.Black, render.Bold)
		verdictExplain = fmt.Sprintf("%d new finding(s), all Disposition=warn", v.IntroducedTotal)
		verdictNote = "warn-only findings do not gate the exit code"
		verdictColor = render.Yellow
	default:
		verdictBadge = render.Style(" PASS ", render.BgGreen, render.Black, render.Bold)
		verdictExplain = "No new findings"
		verdictNote = "Exit code 0 (clean)"
		verdictColor = render.Green
	}
	outcomeLines := []string{
		verdictBadge,
		"",
		render.Style(verdictExplain, render.White, render.Bold),
		render.Style(verdictNote, render.Dim),
	}

	// Findings Delta — all kinds, all buckets. Sum equals the count of
	// rows shown in the list below.
	bucketLines := []string{
		render.Style(fmt.Sprintf("%d New", v.IntroducedTotal), verdictDeltaColor(v.IntroducedTotal, render.Red), render.Bold),
		render.Style(fmt.Sprintf("%d Old", v.PersistedTotal), render.Yellow, render.Bold),
		render.Style(fmt.Sprintf("%d Fixed", v.ResolvedTotal), verdictDeltaColor(v.ResolvedTotal, render.Green), render.Bold),
	}

	// By-Kind breakdown reads AuditFinding.Kind directly. This is what
	// the user sees on the Overview's "Findings" card AND on the Findings
	// tab's grouping axis when they press `g` to group by kind, so the
	// numbers stay consistent across the entire UI.
	byKind := map[string]int{}
	for _, bucket := range [][]output.AuditFinding{m.payload.Audit.Introduced, m.payload.Audit.Persisted, m.payload.Audit.Resolved} {
		for _, f := range bucket {
			byKind[findingKindOf(f)]++
		}
	}
	kindLines := []string{}
	for _, k := range []string{"vulnerability", "license", "package", "other"} {
		if n := byKind[k]; n > 0 {
			kindLines = append(kindLines, render.Style(fmt.Sprintf("%d %s", n, k), kindColor(k), render.Bold))
		}
	}
	if len(kindLines) == 0 {
		kindLines = []string{render.Style("(no findings)", render.Dim)}
	}

	return []listPanel{
		{title: "Audit Outcome", lines: outcomeLines, color: verdictColor, weight: 2},
		{title: "Findings Delta", lines: bucketLines, color: render.Cyan, weight: 2},
		{title: "By Kind", lines: kindLines, color: render.Magenta, weight: 2},
	}
}

// kindColor maps a FindingKind to its display color. Used in any panel
// that visualizes per-kind counts.
func kindColor(kind string) string {
	switch strings.ToLower(kind) {
	case "vulnerability":
		return render.Red
	case "license":
		return render.Yellow
	case "package":
		return render.Cyan
	}
	return render.Dim
}

// vulnsOutcomePanels is the analogue of findingsOutcomePanels but scoped
// to vulnerability-kind findings — so the outcome on the Vulnerabilities
// tab agrees with the rows shown below.
func (m *diffModel) vulnsOutcomePanels() []listPanel {
	v := m.auditVerdict()
	if !v.Ran {
		return []listPanel{{
			title: "Audit Outcome (this tab)",
			lines: []string{
				render.Style(" NOT EVALUATED ", render.BgYellow, render.Black, render.Bold),
				"",
				render.Style("Audit was not run.", render.Dim),
				render.Style("Re-run with --enrich --audit", render.Dim),
				render.Style("to evaluate vulnerabilities.", render.Dim),
			},
			color:  render.Yellow,
			weight: 2,
		}}
	}
	var verdictBadge, verdictExplain, verdictNote, verdictColor string
	switch {
	case v.FailingIntroducedVuln > 0:
		verdictBadge = render.Style(" FAIL ", render.BgRed, render.White, render.Bold)
		verdictExplain = fmt.Sprintf("%d new vulnerability(ies) gate exit code", v.FailingIntroducedVuln)
		verdictNote = "This tab's vulnerabilities would FAIL the audit"
		verdictColor = render.Red
	case v.IntroducedVuln > 0:
		verdictBadge = render.Style(" PASS (warn-only) ", render.BgYellow, render.Black, render.Bold)
		verdictExplain = fmt.Sprintf("%d new vuln(s), all Disposition=warn", v.IntroducedVuln)
		verdictNote = "warn-only vulnerabilities do not gate the exit code"
		verdictColor = render.Yellow
	default:
		verdictBadge = render.Style(" PASS ", render.BgGreen, render.Black, render.Bold)
		verdictExplain = "No new vulnerabilities"
		verdictNote = "Vulnerabilities tab is clean for this diff"
		verdictColor = render.Green
	}
	runLevel := "Run exit code: 0 (PASS)"
	switch {
	case v.FailingIntroduced == 0 && v.IntroducedTotal > 0:
		runLevel = "Run exit code: 0 (warn-only)"
	case v.FailingIntroduced > 0:
		runLevel = fmt.Sprintf("Run exit code: 2 (FAIL — %d failing: %d vuln + %d policy)",
			v.FailingIntroduced, v.FailingIntroducedVuln, v.FailingIntroducedNonVuln)
	}
	outcomeLines := []string{
		verdictBadge,
		"",
		render.Style(verdictExplain, render.White, render.Bold),
		render.Style(verdictNote, render.Dim),
		render.Style(runLevel, render.Dim),
	}
	bucketLines := []string{
		render.Style(fmt.Sprintf("%d New", v.IntroducedVuln), verdictDeltaColor(v.IntroducedVuln, render.Red), render.Bold),
		render.Style(fmt.Sprintf("%d Old", v.PersistedVuln), render.Yellow, render.Bold),
		render.Style(fmt.Sprintf("%d Fixed", v.ResolvedVuln), verdictDeltaColor(v.ResolvedVuln, render.Green), render.Bold),
	}
	// By-severity scoped to vuln-kind across all three buckets — gives the
	// reader a quick read of what kinds of severities the diff touched.
	severity := map[string]int{}
	for _, bucket := range [][]output.AuditFinding{m.payload.Audit.Introduced, m.payload.Audit.Persisted, m.payload.Audit.Resolved} {
		for _, f := range bucket {
			if !isVulnerabilityFinding(f) {
				continue
			}
			sev := strings.ToLower(strings.TrimSpace(f.Severity))
			if sev == "" {
				sev = "unknown"
			}
			severity[sev]++
		}
	}
	severityLines := []string{}
	for _, sev := range []string{"critical", "high", "medium", "low", "unknown"} {
		if n := severity[sev]; n > 0 {
			severityLines = append(severityLines, render.Style(fmt.Sprintf("%d %s", n, titleCase(sev)), render.Red, render.Bold))
		}
	}
	if len(severityLines) == 0 {
		severityLines = []string{render.Style("(no vulnerabilities)", render.Dim)}
	}
	return []listPanel{
		{title: "Audit Outcome (this tab)", lines: outcomeLines, color: verdictColor, weight: 2},
		{title: "Vuln Deltas (this tab)", lines: bucketLines, color: render.Cyan, weight: 2},
		{title: "By Severity (this tab)", lines: severityLines, color: render.Red, weight: 2},
	}
}

// verdictDeltaColor dims a 0-valued count so PASS/empty diffs feel quiet.
func verdictDeltaColor(n int, color string) string {
	if n == 0 {
		return render.Dim
	}
	return color
}

func (m *diffModel) buildAuditTab(cfg auditTabConfig) *listModel {
	deltas := m.auditDeltas(cfg.keep)
	emptyState := fmt.Sprintf("No %s deltas were found.", cfg.itemNoun)
	if m.payload.Audit == nil {
		if m.enrichEnabled {
			emptyState = fmt.Sprintf("Enrichment ran but no %s deltas were produced.", cfg.itemNoun)
		} else {
			emptyState = fmt.Sprintf("No %s data. Run with --enrich --audit to populate.", cfg.itemNoun)
		}
	}

	group := cfg.group
	if group == "" {
		group = "status"
	}
	groups := make(map[string][]auditDelta)
	for _, d := range deltas {
		groups[auditGroupKey(d, group)] = append(groups[auditGroupKey(d, group)], d)
	}
	keys := sortedAuditGroupKeys(groups, group)

	items := make([]listItem, 0)
	for _, key := range keys {
		groupItems := groups[key]
		groupKey := group + ":" + key
		isExpanded := expandedValue(cfg.expanded, groupKey, true)
		items = append(items, listItem{
			title:    fmt.Sprintf("%s (%d)", auditGroupLabel(key, group), len(groupItems)),
			subtitle: group,
			details:  auditGroupDetails(key, group, groupItems, cfg.itemNoun),
			key:      groupKey,
			canOpen:  len(groupItems) > 0,
			expanded: isExpanded,
		})
		if !isExpanded {
			continue
		}
		for _, d := range groupItems {
			items = append(items, listItem{
				title:    auditDeltaTitle(d),
				subtitle: d.status,
				badges:   auditDeltaBadges(d),
				details:  auditDeltaDetails(d),
				depth:    1,
				tree:     "  ",
			})
		}
	}

	groupHints := "g cycles group"
	if cfg.groupHints != "" {
		groupHints = "g cycles group (" + cfg.groupHints + ")"
	}
	controls := []string{
		keyHint("/", "search") + " " + keyHint("g", "group") + " " + keyHint("Enter", "focus details") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all"),
		render.Style("Group: ", render.Dim) + render.Style(groupLabel(group), render.BgYellow, render.Bold) +
			render.Style(" | Count: ", render.Dim) + fmt.Sprintf("%d", len(deltas)),
	}
	if m.payload.Audit != nil {
		controls[1] += render.Style(" | New: ", render.Dim) + render.Style(fmt.Sprintf("%d", auditCount(deltas, "introduced")), render.Red, render.Bold) +
			render.Style(" | Old: ", render.Dim) + render.Style(fmt.Sprintf("%d", auditCount(deltas, "persisted")), render.Yellow, render.Bold) +
			render.Style(" | Fixed: ", render.Dim) + render.Style(fmt.Sprintf("%d", auditCount(deltas, "resolved")), render.Green, render.Bold)
	}
	return &listModel{
		controls:       controls,
		listTitle:      fmt.Sprintf("%s (%d)", cfg.listLabel, len(deltas)),
		detailTitle:    cfg.listLabel + " Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; " + groupHints + "; → expands; Enter focuses details; 1-7 switch tabs",
		emptyState:     emptyState,
		items:          items,
	}
}

func groupLabel(group string) string {
	switch group {
	case "status":
		return "Status"
	case "severity":
		return "Severity"
	case "package":
		return "Package"
	case "license":
		return "License"
	case "manifest":
		return "Manifest"
	case "kind":
		return "Kind (Auditor)"
	case "category":
		return "Category"
	case "recognition":
		return "Recognition"
	}
	if group == "" {
		return "Status"
	}
	return titleCase(group)
}

func auditCount(deltas []auditDelta, status string) int {
	n := 0
	for _, d := range deltas {
		if d.status == status {
			n++
		}
	}
	return n
}

func auditGroupKey(d auditDelta, group string) string {
	switch group {
	case "severity":
		sev := strings.ToLower(strings.TrimSpace(d.severity))
		if sev == "" {
			sev = "unknown"
		}
		return sev
	case "package":
		name := render.DiffPackageDisplayName(d.finding.Package)
		if name == "" {
			return "unknown"
		}
		return name
	case "kind":
		// "kind" axis groups by AuditFinding.Kind — the actual finding
		// kind (vulnerability / license / package / other), NOT the
		// auditor name. This is the dimension users want when they ask
		// "what kind of policy problems do I have on this diff?"
		return findingKindOf(d.finding)
	default:
		return d.status
	}
}

func auditGroupLabel(key, group string) string {
	switch group {
	case "status":
		return titleCase(key)
	case "severity":
		return strings.ToUpper(key)
	case "kind":
		return titleCase(key) // "license" → "License", "package" → "Package", ...
	case "package":
		return key
	default:
		return key
	}
}

func sortedAuditGroupKeys(groups map[string][]auditDelta, group string) []string {
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		switch group {
		case "status":
			return auditStatusOrder(keys[i]) < auditStatusOrder(keys[j])
		case "severity":
			return severityRank(keys[i]) < severityRank(keys[j])
		case "kind":
			return findingKindOrder(keys[i]) < findingKindOrder(keys[j])
		default:
			return keys[i] < keys[j]
		}
	})
	return keys
}

// findingKindOrder controls the row order when grouping the Findings tab
// by kind. Vulnerabilities float to the top because they're the most
// security-critical; everything else lands underneath alphabetically.
func findingKindOrder(kind string) int {
	switch strings.ToLower(kind) {
	case "vulnerability":
		return 0
	case "license":
		return 1
	case "package":
		return 2
	}
	return 3
}

func auditStatusOrder(s string) int {
	switch strings.ToLower(s) {
	case "introduced":
		return 0
	case "persisted":
		return 1
	case "resolved":
		return 2
	}
	return 3
}

func auditDeltaTitle(d auditDelta) string {
	id := strings.TrimSpace(d.finding.ID)
	if id == "" {
		id = "(no id)"
	}
	pkg := render.DiffPackageDisplayName(d.finding.Package)
	if pkg == "" {
		return id
	}
	return id + "  " + render.Style("— "+pkg, render.Dim)
}

func auditDeltaBadges(d auditDelta) []badge {
	// Subtitle (rendered via statusBadge) already shows the New/Old/Fixed
	// audit-delta-status badge for this row — adding a second copy here
	// was the duplicate the user flagged on the Vulnerabilities and
	// Findings tabs. Severity stays as its own badge.
	out := make([]badge, 0, 1)
	if sev := strings.TrimSpace(d.severity); sev != "" {
		out = append(out, badge{label: strings.ToUpper(sev), kind: "severity-" + strings.ToLower(sev)})
	}
	return out
}

func auditDeltaDetails(d auditDelta) []string {
	f := d.finding
	lines := []string{
		render.Style(valueOrDash(f.ID), render.Bold, render.Red),
	}
	if f.Title != "" && f.Title != f.ID {
		lines = append(lines, render.Style("  "+f.Title, render.White, render.Bold))
	}
	lines = append(lines,
		"",
		render.Style("Status", render.Bold, render.Cyan),
		render.Style("  Delta status: ", render.Dim)+statusText(auditStatusLabel(d.status)),
		render.Style("  Disposition: ", render.Dim)+valueOrDash(string(f.Disposition)),
		render.Style("  Severity: ", render.Dim)+severityText(f.Severity),
		"",
		render.Style("Classification", render.Bold, render.Magenta),
		render.Style("  Kind: ", render.Dim)+valueOrDash(f.Kind),
		render.Style("  Auditor: ", render.Dim)+valueOrDash(f.Auditor),
		render.Style("  Source: ", render.Dim)+valueOrDash(f.Source),
		"",
		render.Style("Package", render.Bold, render.Magenta),
		render.Style("  Display: ", render.Dim)+valueOrDash(render.DiffPackageDisplayName(f.Package)),
		render.Style("  Purl: ", render.Dim)+valueOrDash(f.Package.Purl),
		render.Style("  Scope: ", render.Dim)+valueOrDash(f.Package.Scope),
	)
	if len(f.Reasons) > 0 {
		lines = append(lines, "", render.Style("Reasons", render.Bold, render.Magenta))
		for _, r := range f.Reasons {
			lines = append(lines, render.Style("  - ", render.Dim)+r)
		}
	}
	if f.Reachability != nil {
		lines = append(lines, "", render.Style("Reachability", render.Bold, render.Yellow))
		lines = append(lines, render.Style("  Tier: ", render.Dim)+valueOrDash(string(f.Reachability.Tier)))
		if f.Reachability.Analyzer != "" {
			lines = append(lines, render.Style("  Analyzer: ", render.Dim)+f.Reachability.Analyzer)
		}
	}
	// For vuln findings include licenses on the affected package so the
	// reader sees the full picture without bouncing to the Components tab.
	if len(f.Package.Licenses) > 0 {
		lines = append(lines, renderLicenseList(f.Package.Licenses)...)
	}
	return lines
}

func auditGroupDetails(key, group string, deltas []auditDelta, noun string) []string {
	if noun == "" {
		noun = "items"
	} else {
		noun = pluralize(noun)
	}
	lines := []string{
		render.Style(auditGroupLabel(key, group), render.Bold, render.Red),
		"",
		render.Style("  Group axis: ", render.Dim) + groupLabel(group),
		render.Style("  "+titleCase(noun)+": ", render.Dim) + fmt.Sprintf("%d", len(deltas)),
	}
	counts := map[string]int{"introduced": 0, "persisted": 0, "resolved": 0}
	severityCounts := make(map[string]int)
	auditorCounts := make(map[string]int)
	for _, d := range deltas {
		counts[d.status]++
		sev := strings.ToLower(strings.TrimSpace(d.severity))
		if sev == "" {
			sev = "unknown"
		}
		severityCounts[sev]++
		aud := strings.TrimSpace(d.finding.Auditor)
		if aud == "" {
			aud = strings.TrimSpace(d.finding.Source)
		}
		if aud == "" {
			aud = "unknown"
		}
		auditorCounts[aud]++
	}
	lines = append(lines,
		render.Style("  New: ", render.Dim)+fmt.Sprintf("%d", counts["introduced"]),
		render.Style("  Old: ", render.Dim)+fmt.Sprintf("%d", counts["persisted"]),
		render.Style("  Fixed: ", render.Dim)+fmt.Sprintf("%d", counts["resolved"]),
	)
	if len(severityCounts) > 1 || (len(severityCounts) == 1 && severityCounts["unknown"] == 0) {
		lines = append(lines, "", render.Style("By severity", render.Bold, render.Magenta))
		for _, sev := range []string{"critical", "high", "medium", "low", "unknown"} {
			if n := severityCounts[sev]; n > 0 {
				lines = append(lines, render.Style("  "+titleCase(sev)+": ", render.Dim)+fmt.Sprintf("%d", n))
			}
		}
	}
	if len(auditorCounts) > 0 {
		lines = append(lines, "", render.Style("By auditor", render.Bold, render.Magenta))
		auditors := make([]string, 0, len(auditorCounts))
		for a := range auditorCounts {
			auditors = append(auditors, a)
		}
		sort.Strings(auditors)
		for _, a := range auditors {
			lines = append(lines, render.Style("  "+a+": ", render.Dim)+fmt.Sprintf("%d", auditorCounts[a]))
		}
	}
	return lines
}

// pluralize is a *very* dumb pluralizer that's fine for our nouns
// ("vulnerability" → "vulnerabilities", "finding" → "findings").
func pluralize(noun string) string {
	if strings.HasSuffix(noun, "y") {
		return strings.TrimSuffix(noun, "y") + "ies"
	}
	if strings.HasSuffix(noun, "s") {
		return noun
	}
	return noun + "s"
}

// --- Licenses tab ---------------------------------------------------------

type licenseDelta struct {
	license  string
	status   string // "introduced", "retired"
	pkg      string
	manifest string
}

func (m *diffModel) collectLicenseDeltas() []licenseDelta {
	out := make([]licenseDelta, 0)
	add := func(status, pkgLabel, manifestLabel string, licenses []output.LicenseRef) {
		for _, lic := range licenses {
			id := strings.TrimSpace(lic.Identifier())
			if id == "" {
				continue
			}
			out = append(out, licenseDelta{license: id, status: status, pkg: pkgLabel, manifest: manifestLabel})
		}
	}
	for _, mf := range m.payload.Results.Manifests {
		mfLabel := render.DiffManifestDisplayLabel(mf)
		for _, change := range mf.Added {
			add("introduced", render.DiffPackageDisplayName(change.Package), mfLabel, change.Package.Licenses)
		}
		for _, change := range mf.Removed {
			add("retired", render.DiffPackageDisplayName(change.Package), mfLabel, change.Package.Licenses)
		}
		for _, change := range mf.Changed {
			before := licenseSet(change.Before.Licenses)
			after := licenseSet(change.After.Licenses)
			for id := range after {
				if _, ok := before[id]; !ok {
					out = append(out, licenseDelta{license: id, status: "introduced", pkg: render.DiffPackageDisplayName(change.After), manifest: mfLabel})
				}
			}
			for id := range before {
				if _, ok := after[id]; !ok {
					out = append(out, licenseDelta{license: id, status: "retired", pkg: render.DiffPackageDisplayName(change.Before), manifest: mfLabel})
				}
			}
		}
	}
	return out
}

func licenseSet(licenses []output.LicenseRef) map[string]struct{} {
	out := make(map[string]struct{}, len(licenses))
	for _, l := range licenses {
		id := strings.TrimSpace(l.Identifier())
		if id == "" {
			continue
		}
		out[id] = struct{}{}
	}
	return out
}

// nextLicenseGroup cycles the grouping axis for the Licenses tab:
//
//	license  → group by SPDX id (each row = a package contributing it)
//	status   → introduced/retired buckets
//	manifest → grouped by manifest
//	category → Permissive / Copyleft / Unknown / Unclassified (scan parity)
//	recognition → recognized / unknown / unrecognized expression
func nextLicenseGroup(group string) string {
	switch group {
	case "license":
		return "status"
	case "status":
		return "manifest"
	case "manifest":
		return "category"
	case "category":
		return "recognition"
	default:
		return "license"
	}
}

func (m *diffModel) buildLicensesTab() *listModel {
	deltas := m.collectLicenseDeltas()
	group := m.licenseGroup
	if group == "" {
		group = "license"
	}
	groups := make(map[string][]licenseDelta)
	for _, d := range deltas {
		key := licenseGroupKeyDiff(d, group)
		groups[key] = append(groups[key], d)
	}
	keys := sortedLicenseGroupKeys(groups, group)

	items := make([]listItem, 0)
	for _, key := range keys {
		groupItems := groups[key]
		groupKey := group + ":" + key
		isExpanded := expandedValue(m.licenseExpanded, groupKey, true)
		items = append(items, listItem{
			title:    fmt.Sprintf("%s (%d)", licenseGroupTitle(key, group), len(groupItems)),
			subtitle: group,
			details:  licenseGroupDetailsDiff(key, group, groupItems),
			key:      groupKey,
			canOpen:  len(groupItems) > 0,
			expanded: isExpanded,
		})
		if !isExpanded {
			continue
		}
		for _, d := range groupItems {
			// Row title: when grouped *by license*, the row shows the
			// affected package (so the user sees which packages contributed
			// this license). For every other axis, the row shows the
			// license name itself.
			rowTitle := d.license
			if group == "license" {
				rowTitle = d.pkg
			}
			items = append(items, listItem{
				title:    rowTitle,
				subtitle: d.status,
				// Subtitle already paints a colored status badge for
				// introduced/retired — no extra explicit badge needed.
				badges:  nil,
				details: licenseDeltaDetails(d),
				depth:   1,
				tree:    "  ",
			})
		}
	}

	introduced, retired := 0, 0
	for _, d := range deltas {
		if d.status == "introduced" {
			introduced++
		} else {
			retired++
		}
	}
	controls := []string{
		keyHint("/", "search") + " " + keyHint("g", "group") + " " + keyHint("Enter", "focus details") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all"),
		render.Style("Group: ", render.Dim) + render.Style(groupLabel(group), render.BgYellow, render.Bold) +
			render.Style(" | Introduced: ", render.Dim) + render.Style(fmt.Sprintf("%d", introduced), render.Green, render.Bold) +
			render.Style(" | Retired: ", render.Dim) + render.Style(fmt.Sprintf("%d", retired), render.Red, render.Bold),
	}
	emptyState := "No license deltas were found."
	return &listModel{
		controls:       controls,
		listTitle:      fmt.Sprintf("Licenses (%d)", len(deltas)),
		detailTitle:    "License Details",
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; g cycles group (license/status/manifest/category/recognition); → expands; Enter focuses details; 1-7 switch tabs",
		emptyState:     emptyState,
		items:          items,
	}
}

func licenseGroupKeyDiff(d licenseDelta, group string) string {
	switch group {
	case "status":
		return d.status
	case "manifest":
		if d.manifest == "" {
			return "(unknown manifest)"
		}
		return d.manifest
	case "category":
		return strings.ToLower(licenseCategory(d.license))
	case "recognition":
		return licenseRecognitionKey(d.license)
	default:
		return d.license
	}
}

// licenseRecognitionKey produces a stable lowercase bucket name for the
// recognition axis. Unlike licenseRecognition (which returns ANSI-colored
// text for display), this returns a plain key suitable for map/sort use.
func licenseRecognitionKey(value string) string {
	switch {
	case isUnknownLicense(value):
		return "unknown"
	case looksLikeSPDXLicense(value):
		return "recognized"
	default:
		return "unrecognized"
	}
}

func licenseGroupTitle(key, group string) string {
	switch group {
	case "status", "category", "recognition":
		return titleCase(key)
	default:
		return key
	}
}

func sortedLicenseGroupKeys(groups map[string][]licenseDelta, group string) []string {
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		switch group {
		case "status":
			order := map[string]int{"introduced": 0, "retired": 1}
			return order[keys[i]] < order[keys[j]]
		case "recognition":
			order := map[string]int{"recognized": 0, "unrecognized": 1, "unknown": 2}
			return order[keys[i]] < order[keys[j]]
		case "category":
			order := map[string]int{"permissive": 0, "copyleft": 1, "unclassified": 2, "unknown": 3}
			ri, rj := order[keys[i]], order[keys[j]]
			if ri != rj {
				return ri < rj
			}
		}
		return keys[i] < keys[j]
	})
	return keys
}

func licenseGroupDetailsDiff(key, group string, deltas []licenseDelta) []string {
	counts := map[string]int{"introduced": 0, "retired": 0}
	uniqueLicenses := make(map[string]int)
	uniquePackages := make(map[string]int)
	uniqueManifests := make(map[string]int)
	for _, d := range deltas {
		counts[d.status]++
		uniqueLicenses[d.license]++
		uniquePackages[d.pkg]++
		uniqueManifests[d.manifest]++
	}
	lines := []string{
		render.Style(licenseGroupTitle(key, group), render.Bold, render.Yellow),
		"",
		render.Style("  Group axis: ", render.Dim) + groupLabel(group),
		render.Style("  Total events: ", render.Dim) + fmt.Sprintf("%d", len(deltas)),
		render.Style("  Introduced: ", render.Dim) + fmt.Sprintf("%d", counts["introduced"]),
		render.Style("  Retired: ", render.Dim) + fmt.Sprintf("%d", counts["retired"]),
		render.Style("  Unique licenses: ", render.Dim) + fmt.Sprintf("%d", len(uniqueLicenses)),
		render.Style("  Unique packages: ", render.Dim) + fmt.Sprintf("%d", len(uniquePackages)),
		render.Style("  Unique manifests: ", render.Dim) + fmt.Sprintf("%d", len(uniqueManifests)),
	}
	// Cross-axis context: when grouped by category, surface the *unique*
	// license IDs that landed in this bucket so the user can see which
	// SPDX expressions contributed.
	if (group == "category" || group == "recognition" || group == "status" || group == "manifest") && len(uniqueLicenses) > 0 {
		ids := make([]string, 0, len(uniqueLicenses))
		for id := range uniqueLicenses {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		lines = append(lines, "", render.Style("Licenses in this group", render.Bold, render.Magenta))
		for _, id := range ids {
			lines = append(lines, render.Style("  - ", render.Dim)+id+render.Style(fmt.Sprintf("  (×%d)", uniqueLicenses[id]), render.Dim))
		}
	}
	return lines
}

func licenseDeltaDetails(d licenseDelta) []string {
	plain := d.license
	return []string{
		render.Style("License Delta", render.Bold, render.Yellow),
		"",
		render.Style("  License: ", render.Dim) + valueOrDash(d.license),
		render.Style("  Category: ", render.Dim) + licenseCategory(plain),
		render.Style("  Recognition: ", render.Dim) + licenseRecognition(plain),
		render.Style("  Status: ", render.Dim) + statusText(d.status),
		render.Style("  Package: ", render.Dim) + valueOrDash(d.pkg),
		render.Style("  Manifest: ", render.Dim) + valueOrDash(d.manifest),
	}
}

// --- Source tab -----------------------------------------------------------

// buildSourceTab plugs into the shared shell skeleton (top bar, tab strip,
// controls, footer) and supplies a bodyOverride that fills the body region
// with two side-by-side boxes — Base on the left, Head on the right. The
// focused side (toggled with `g`) is the one whose key events (search,
// expand, scroll) take effect; the unfocused side is rendered as static
// tree text alongside it.
func (m *diffModel) buildSourceTab() *listModel {
	focused := m.sourceSide
	if focused == "" {
		focused = diffSourceBase
	}
	otherLabel := "Head"
	if focused == diffSourceHead {
		otherLabel = "Base"
	}

	// Build BOTH sides' items up front — the focused side's items also
	// power list-level state (visibleItemIndices, expand, search) by
	// living in the listModel.items slice.
	baseItems := diffSourceItems(m.baseGraph, m.sourceBaseExpanded, "base")
	headItems := diffSourceItems(m.headGraph, m.sourceHeadExpanded, "head")
	focusedItems := baseItems
	if focused == diffSourceHead {
		focusedItems = headItems
	}

	controls := []string{
		keyHint("/", "search") + " " + keyHint("g", "switch focus") + " " + keyHint("Enter", "focus details") + " " + keyHint("→", "expand") + " " + keyHint("←", "collapse") + " " + keyHint("]", "expand all") + " " + keyHint("[", "collapse all"),
		render.Style("Focused: ", render.Dim) + render.Style(strings.ToUpper(string(focused)), render.BgYellow, render.Bold) +
			render.Style(" | g → "+otherLabel, render.Dim) +
			render.Style(fmt.Sprintf(" | Base nodes: %d", len(baseItems)), render.Dim) +
			render.Style(fmt.Sprintf(" | Head nodes: %d", len(headItems)), render.Dim),
	}

	list := &listModel{
		controls:       controls,
		listTitle:      "Source",
		detailTitle:    "-",
		navigationHelp: interactiveCommonNavigationHelp + "; → expands; Enter focuses details/collapses source nodes",
		filterHelp:     "Use / to search; g switches focus base/head; Enter/→/← expand & collapse; 1-7 switch tabs",
		emptyState:     "No source graph available.",
		items:          focusedItems,
	}
	list.bodyOverride = func(width, height int) []string {
		return m.renderSourceBody(width, height, focused, baseItems, headItems, list)
	}
	return list
}

// renderSourceBody fills the body region with two equal-width tree boxes.
// The focused side is rendered from the live listModel (so selection,
// scrolling, and search highlighting work there); the other side is
// rendered as static tree text.
func (m *diffModel) renderSourceBody(width, height int, focused diffSourceSide, baseItems, headItems []listItem, list *listModel) []string {
	gap := 1
	leftWidth := (width - gap) / 2
	rightWidth := width - leftWidth - gap

	leftTitle := "Base"
	rightTitle := "Head"
	leftColor := render.Cyan
	rightColor := render.Magenta
	if focused == diffSourceBase {
		leftTitle = "Base (focused)"
		leftColor = render.Yellow
	} else {
		rightTitle = "Head (focused)"
		rightColor = render.Yellow
	}

	leftLines := sourceBoxBody(baseItems, focused == diffSourceBase, list, leftWidth-2, height-2)
	rightLines := sourceBoxBody(headItems, focused == diffSourceHead, list, rightWidth-2, height-2)

	leftBox := boxView(leftTitle, leftLines, leftWidth, height, leftColor)
	rightBox := boxView(rightTitle, rightLines, rightWidth, height, rightColor)

	out := make([]string, 0, height)
	for i := 0; i < height; i++ {
		l := ""
		r := ""
		if i < len(leftBox) {
			l = leftBox[i]
		}
		if i < len(rightBox) {
			r = rightBox[i]
		}
		out = append(out, l+strings.Repeat(" ", gap)+r)
	}
	return out
}

// sourceBoxBody renders one side's tree content. When `live` is true, the
// listModel's selection / scroll / search state highlights the focused row.
func sourceBoxBody(items []listItem, live bool, list *listModel, width, height int) []string {
	if len(items) == 0 {
		return []string{render.Style("(empty)", render.Dim)}
	}
	if !live {
		// Inactive side: simple static tree text.
		lines := make([]string, 0, height)
		for i, it := range items {
			if i >= height {
				lines = append(lines, render.Style(fmt.Sprintf("… +%d more", len(items)-i), render.Dim))
				break
			}
			lines = append(lines, truncateToWidth(sourceItemPlain(it), width))
		}
		return lines
	}
	// Focused side: drive scrolling/selection from the live listModel.
	visible := list.visibleItemIndices()
	if len(visible) == 0 {
		return []string{render.Style(list.emptyState, render.Yellow, render.Bold)}
	}
	return list.visibleListLines(width, height, visible)
}

// sourceItemPlain renders one listItem as a plain (no-highlight) tree line.
func sourceItemPlain(it listItem) string {
	marker := "  "
	if it.canOpen {
		if it.expanded {
			marker = render.Style("▾ ", render.Cyan)
		} else {
			marker = render.Style("▸ ", render.Dim)
		}
	}
	return it.tree + marker + it.title
}

func diffSourceItems(consolidated sdk.ConsolidatedGraph, expanded map[string]bool, sidePrefix string) []listItem {
	items := []listItem{sourceNode(fmt.Sprintf("%s: {}", sidePrefix), "root", "", 0, true, expandedValue(expanded, "root", true))}
	if !expandedValue(expanded, "root", true) {
		return items
	}

	manifestCount := len(consolidated.Manifests)
	subprojectCount := len(consolidated.Subprojects)
	graph, _ := graphFromConsolidated(consolidated)
	packageCount := 0
	relationshipCnt := 0
	if graph != nil {
		packageCount = graph.Size()
		relationshipCnt = relationshipCount(graph)
	}
	sections := []struct {
		key   string
		title string
		last  bool
	}{
		{"subprojects", fmt.Sprintf("subprojects: [] (%d items)", subprojectCount), false},
		{"manifests", fmt.Sprintf("manifests: [] (%d items)", manifestCount), false},
		{"packages", fmt.Sprintf("packages: [] (%d items)", packageCount), false},
		{"relationships", fmt.Sprintf("relationships: [] (%d items)", relationshipCnt), true},
	}
	for _, s := range sections {
		tree := "├─ "
		if s.last {
			tree = "└─ "
		}
		isExpanded := expandedValue(expanded, s.key, false)
		items = append(items, sourceNode(s.title, s.key, tree, 1, true, isExpanded))
		if !isExpanded {
			continue
		}
		prefix := "│  "
		if s.last {
			prefix = "   "
		}
		switch s.key {
		case "subprojects":
			for i, sub := range consolidated.Subprojects {
				last := i == len(consolidated.Subprojects)-1
				tree := prefix + branch(last)
				items = append(items, sourceNode(fmt.Sprintf("%q: {detector: %q, roots: %d}", sub.Subproject.RelativePath, sub.DetectorName, len(sub.RootManifestIDs)), "subproject:"+sub.Subproject.RelativePath, tree, 2, false, false))
			}
		case "manifests":
			for i, mf := range consolidated.Manifests {
				last := i == len(consolidated.Manifests)-1
				tree := prefix + branch(last)
				items = append(items, sourceNode(fmt.Sprintf("%q: {detector: %q, technique: %q}", mf.Entry.Manifest.Path, mf.DetectorName, mf.Technique), "manifest:"+mf.Entry.Manifest.Path, tree, 2, false, false))
			}
		case "packages":
			if graph == nil {
				items = append(items, sourceNode("(no consolidated graph)", "", prefix+"└─ ", 2, false, false))
				break
			}
			pkgs := graph.Nodes()
			sort.Slice(pkgs, func(i, j int) bool { return packageSortKey(pkgs[i]) < packageSortKey(pkgs[j]) })
			limit := len(pkgs)
			truncated := false
			if limit > 200 {
				limit = 200
				truncated = true
			}
			for i := 0; i < limit; i++ {
				pkg := pkgs[i]
				last := i == limit-1 && !truncated
				tree := prefix + branch(last)
				key := "package:" + pkg.ID
				isExp := expandedValue(expanded, key, false)
				items = append(items, sourceNode(fmt.Sprintf("%q: {}", pkg.ID), key, tree, 2, true, isExp))
				if !isExp {
					continue
				}
				childPrefix := prefix
				if last {
					childPrefix += "   "
				} else {
					childPrefix += "│  "
				}
				items = append(items, sourceLeafItems(packageRawLines(pkg), childPrefix)...)
			}
			if truncated {
				items = append(items, sourceNode(fmt.Sprintf("(showing 200 of %d packages)", len(pkgs)), "", prefix+"└─ ", 2, false, false))
			}
		case "relationships":
			if graph == nil {
				items = append(items, sourceNode("(no consolidated graph)", "", prefix+"└─ ", 2, false, false))
				break
			}
			edges := relationshipRawLines(graph)
			limit := len(edges)
			truncated := false
			if limit > 200 {
				limit = 200
				truncated = true
			}
			items = append(items, sourceLeafItems(edges[:limit], prefix)...)
			if truncated {
				items = append(items, sourceNode(fmt.Sprintf("(showing 200 of %d edges)", len(edges)), "", prefix+"└─ ", 2, false, false))
			}
		}
	}
	return items
}

func graphFromConsolidated(c sdk.ConsolidatedGraph) (*sdk.Graph, error) {
	if c.Graphs == nil {
		return nil, nil
	}
	return c.Graphs.ConsolidatedGraph()
}
