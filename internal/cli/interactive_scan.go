package cli

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func newScanInteractiveModel(project output.ProjectDescriptor, consolidated model.ConsolidatedGraph, graphValue *model.Graph, findings []model.Finding) *interactiveScanModel {
	return newScanNavigatorModel("Bomly Interactive Scan", project, consolidated, graphValue, findings)
}

func newScanNavigatorModel(titlePrefix string, project output.ProjectDescriptor, consolidated model.ConsolidatedGraph, graphValue *model.Graph, findings []model.Finding) *interactiveScanModel {
	manifests := interactiveManifestRows(consolidated)
	manifestByID := make(map[string]interactiveListPackageRow, len(manifests))
	for _, manifest := range manifests {
		manifestByID[manifest.id] = manifest
	}

	model := &interactiveScanModel{
		titlePrefix:       titlePrefix,
		project:           project,
		graphValue:        graphValue,
		explainMode:       strings.Contains(strings.ToLower(titlePrefix), "explain"),
		manifests:         manifests,
		manifestByID:      manifestByID,
		mode:              interactiveScanModeManifests,
		allowManifestExit: len(manifests) > 1,
		findings:          findings,
		activeView:        interactiveScanViewPackages,
	}
	if len(manifests) == 1 {
		model.mode = interactiveScanModeComponents
		model.currentManifestID = manifests[0].id
	}
	model.list = model.buildCurrentListModel()
	return model
}

func (m *interactiveScanModel) View(width, height int) string {
	if m == nil || m.list == nil {
		return ""
	}
	return m.list.View(width, height)
}

func (m *interactiveScanModel) Move(delta int) {
	if m == nil || m.list == nil {
		return
	}
	m.list.Move(delta)
}

func (m *interactiveScanModel) ScrollDetails(delta int) {
	if m == nil || m.list == nil {
		return
	}
	m.list.ScrollDetails(delta)
}

func (m *interactiveScanModel) Home() {
	if m == nil || m.list == nil {
		return
	}
	m.list.Home()
}

func (m *interactiveScanModel) End() {
	if m == nil || m.list == nil {
		return
	}
	m.list.End()
}

func (m *interactiveScanModel) BeginSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.BeginSearch()
}

func (m *interactiveScanModel) AppendSearch(value string) {
	if m == nil || m.list == nil {
		return
	}
	m.list.AppendSearch(value)
}

func (m *interactiveScanModel) BackspaceSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.BackspaceSearch()
}

func (m *interactiveScanModel) CancelSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.CancelSearch()
}

func (m *interactiveScanModel) ConfirmSearch() {
	if m == nil || m.list == nil {
		return
	}
	m.list.ConfirmSearch()
}

func (m *interactiveScanModel) IsSearching() bool {
	if m == nil || m.list == nil {
		return false
	}
	return m.list.IsSearching()
}

func (m *interactiveScanModel) CycleView() {
	if m == nil {
		return
	}
	switch m.activeView {
	case interactiveScanViewPackages:
		m.activeView = interactiveScanViewVulns
	case interactiveScanViewVulns:
		m.activeView = interactiveScanViewLicenses
	default:
		m.activeView = interactiveScanViewPackages
	}
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) CycleRelationshipFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages || m.mode != interactiveScanModeComponents {
		return
	}
	m.relationshipFilter = nextInteractiveRelationshipFilter(m.relationshipFilter, m.explainMode)
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) CycleScopeFilter() {
	if m == nil || m.activeView != interactiveScanViewPackages || m.mode != interactiveScanModeComponents {
		return
	}
	m.scopeFilter = nextInteractiveScopeFilter(m.scopeFilter)
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) CycleSeverityFilter() {
	if m == nil {
		return
	}
	switch m.activeView {
	case interactiveScanViewVulns:
		// always applicable
	case interactiveScanViewPackages:
		if m.mode != interactiveScanModeComponents {
			return
		}
	default:
		return
	}
	m.severityFilter = nextInteractiveSeverityFilter(m.severityFilter)
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) OpenSelected() {
	if m == nil || m.list == nil || m.activeView != interactiveScanViewPackages || m.mode != interactiveScanModeManifests {
		return
	}
	visible := m.list.visibleItemIndices()
	if len(visible) == 0 {
		return
	}
	item := m.list.items[visible[m.list.selectedVisibleIndex(visible)]]
	manifestID := interactiveManifestIDFromTitle(item.title)
	if manifestID == "" {
		for id, manifest := range m.manifestByID {
			if manifest.displayName == item.title {
				manifestID = id
				break
			}
		}
	}
	if manifestID == "" {
		return
	}
	m.mode = interactiveScanModeComponents
	m.currentManifestID = manifestID
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) GoBack() {
	if !m.CanGoBack() {
		return
	}
	m.mode = interactiveScanModeManifests
	m.currentManifestID = ""
	m.list = m.buildCurrentListModel()
}

func (m *interactiveScanModel) CanGoBack() bool {
	if m == nil {
		return false
	}
	return m.activeView == interactiveScanViewPackages && m.mode == interactiveScanModeComponents && m.allowManifestExit
}

func (m *interactiveScanModel) buildCurrentListModel() *interactiveListModel {
	switch m.activeView {
	case interactiveScanViewVulns:
		return m.buildVulnsListModel()
	case interactiveScanViewLicenses:
		return m.buildLicensesListModel()
	default:
		if m.mode == interactiveScanModeComponents {
			manifest, ok := m.manifestByID[m.currentManifestID]
			if ok {
				return m.buildComponentListModel(manifest)
			}
		}
		return m.buildManifestListModel()
	}
}

func (m *interactiveScanModel) buildManifestListModel() *interactiveListModel {
	items := make([]interactiveListItem, 0, len(m.manifests))
	for _, manifest := range m.manifests {
		title := manifest.displayName + " [" + manifest.id + "]"
		items = append(items, interactiveListItem{
			title:    title,
			subtitle: "manifest",
			details:  interactiveManifestDetails(m.graphValue, manifest),
		})
	}

	packageCount := 0
	if m.graphValue != nil {
		packageCount = m.graphValue.Size()
	}

	return &interactiveListModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: []string{
			ansiStyled("Tab: [PACKAGES] | Vulnerabilities | Licenses", ansiDim),
			ansiStyled(fmt.Sprintf("Manifests %d", len(m.manifests)), ansiCyan, ansiBold),
			ansiStyled(fmt.Sprintf("Packages  %d", packageCount), ansiCyan, ansiBold),
			ansiStyled("Project   ", ansiDim) + m.project.Path,
			ansiStyled("Ecosystem ", ansiDim) + valueOrDash(m.project.Ecosystem),
		},
		navigationHelp: interactiveCommonNavigationHelp + "; Enter opens selected manifest",
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search",
		emptyState:     "No manifests were found in the dependency graph.",
		items:          items,
	}
}

func (m *interactiveScanModel) buildVulnsListModel() *interactiveListModel {
	all := make([]model.Finding, 0, len(m.findings))
	for _, f := range m.findings {
		if f.Kind == model.FindingKindVulnerability {
			all = append(all, f)
		}
	}

	// Apply severity filter.
	filtered := all
	if m.severityFilter != "" {
		filtered = make([]model.Finding, 0, len(all))
		for _, f := range all {
			if strings.EqualFold(f.Severity, m.severityFilter) {
				filtered = append(filtered, f)
			}
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		ri, rj := interactiveSeverityRank(filtered[i].Severity), interactiveSeverityRank(filtered[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return filtered[i].ID < filtered[j].ID
	})

	items := make([]interactiveListItem, 0, len(filtered))
	for _, f := range filtered {
		pkgName := ""
		if f.Package != nil {
			pkgName = f.Package.Name
			if f.Package.Version != "" {
				pkgName += "@" + f.Package.Version
			}
		}
		// Append pkgName directly to the title so it renders as plain (white)
		// text without any background-color badge that causes contrast issues.
		titleStr := f.ID
		if pkgName != "" {
			titleStr += "  " + pkgName
		}
		items = append(items, interactiveListItem{
			title:  titleStr,
			badges: []interactiveBadge{{label: f.Severity, kind: "severity-" + strings.ToLower(f.Severity)}},
			details: []string{
				ansiStyled("ID        ", ansiDim) + valueOrDash(f.ID),
				ansiStyled("Severity  ", ansiDim) + interactiveSeverityText(f.Severity),
				ansiStyled("Package   ", ansiDim) + valueOrDash(pkgName),
				ansiStyled("Title     ", ansiDim) + valueOrDash(f.Title),
				ansiStyled("Source    ", ansiDim) + valueOrDash(f.Source),
			},
		})
	}

	return &interactiveListModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: []string{
			ansiStyled("Tab: Packages | [VULNERABILITIES] | Licenses", ansiDim),
			ansiStyled("Filter severity ", ansiDim) + valueOrDash(m.severityFilter),
			ansiStyled(fmt.Sprintf("Showing %d / %d", len(filtered), len(all)), ansiCyan, ansiBold),
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; v cycles severity filter",
		emptyState:     "No policy findings found. Run with --audit to evaluate enriched vulnerability data.",
		items:          items,
	}
}

func (m *interactiveScanModel) buildLicensesListModel() *interactiveListModel {
	rows := interactiveLicenseRows(m.graphValue)
	items := make([]interactiveListItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, interactiveListItem{
			title:    row.license,
			subtitle: fmt.Sprintf("%d package(s)", len(row.packages)),
			details:  interactiveLicenseDetails(row),
		})
	}

	return &interactiveListModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: []string{
			ansiStyled("Tab: Packages | Vulnerabilities | [LICENSES]", ansiDim),
			ansiStyled(fmt.Sprintf("Unique licenses %d", len(rows)), ansiCyan, ansiBold),
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search",
		emptyState:     "No license information found.",
		items:          items,
	}
}

type interactiveLicenseRow struct {
	license  string
	packages []interactiveLicensePackageRef
}

type interactiveLicensePackageRef struct {
	id          string
	displayName string
	version     string
	scope       string
}

func interactiveLicenseRows(graphValue *model.Graph) []interactiveLicenseRow {
	if graphValue == nil {
		return nil
	}

	rowsByLicense := make(map[string]map[string]interactiveLicensePackageRef)
	for _, pkg := range graphValue.Packages() {
		if pkg == nil {
			continue
		}
		for _, licenseValue := range pkg.LicenseValues() {
			licenseValue = strings.TrimSpace(licenseValue)
			if licenseValue == "" {
				continue
			}
			packageRefs, ok := rowsByLicense[licenseValue]
			if !ok {
				packageRefs = make(map[string]interactiveLicensePackageRef)
				rowsByLicense[licenseValue] = packageRefs
			}
			packageRefs[pkg.ID] = interactiveLicensePackageRef{
				id:          pkg.ID,
				displayName: pkg.DisplayName(),
				version:     pkg.Version,
				scope:       pkg.Scope,
			}
		}
	}

	rows := make([]interactiveLicenseRow, 0, len(rowsByLicense))
	for licenseValue, packageRefs := range rowsByLicense {
		packages := make([]interactiveLicensePackageRef, 0, len(packageRefs))
		for _, pkg := range packageRefs {
			packages = append(packages, pkg)
		}
		sort.Slice(packages, func(i, j int) bool {
			if packages[i].displayName != packages[j].displayName {
				return packages[i].displayName < packages[j].displayName
			}
			if packages[i].version != packages[j].version {
				return packages[i].version < packages[j].version
			}
			return packages[i].id < packages[j].id
		})
		rows = append(rows, interactiveLicenseRow{
			license:  licenseValue,
			packages: packages,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].license < rows[j].license
	})
	return rows
}

func interactiveLicenseDetails(row interactiveLicenseRow) []string {
	lines := []string{
		ansiStyled("License", ansiBold, ansiCyan),
		ansiStyled("  Identifier: ", ansiDim) + valueOrDash(row.license),
		ansiStyled("  Package count: ", ansiDim) + fmt.Sprintf("%d", len(row.packages)),
		"",
		ansiStyled("Packages Using This License", ansiBold, ansiMagenta),
	}
	if len(row.packages) == 0 {
		lines = append(lines, ansiStyled("  (none)", ansiDim))
		return lines
	}
	for _, pkg := range row.packages {
		label := pkg.displayName
		if pkg.version != "" {
			label += "@" + pkg.version
		}
		if pkg.scope != "" {
			label += " [" + pkg.scope + "]"
		}
		lines = append(lines, ansiStyled("  - ", ansiDim)+label)
	}
	return lines
}

func (m *interactiveScanModel) buildComponentListModel(manifest interactiveListPackageRow) *interactiveListModel {
	if m.explainMode {
		return m.buildExplainComponentListModel(manifest)
	}
	rootPkg, _ := m.graphValue.Package(manifest.rootID)
	groups := interactiveRootDependencies(m.graphValue, manifest.rootID)

	// Build rows: root first, then direct, then transitive
	rows := make([]interactiveListPackageRow, 0, 1+len(groups.direct)+len(groups.transitive))

	// Add root package first
	if rootPkg != nil {
		rows = append(rows, interactivePackageRowFromGraph(rootPkg, "root"))
	}

	for _, pkg := range groups.direct {
		rows = append(rows, interactivePackageRowFromGraph(pkg, "direct"))
	}
	for _, pkg := range groups.transitive {
		rows = append(rows, interactivePackageRowFromGraph(pkg, "transitive"))
	}
	rows = filterInteractivePackageRows(rows, m.relationshipFilter, m.scopeFilter)

	// Compute highest severity per package for badge display, filtering, and sorting.
	maxSevByID := interactiveMaxSeverityByPkgID(m.findings)

	// Apply severity filter.
	if m.severityFilter != "" {
		kept := rows[:0]
		for _, row := range rows {
			if strings.EqualFold(maxSevByID[row.id], m.severityFilter) {
				kept = append(kept, row)
			}
		}
		rows = kept
	}

	// Sort: highest severity first, then relationship, then ID.
	sort.Slice(rows, func(i, j int) bool {
		si := interactiveSeverityRank(maxSevByID[rows[i].id])
		sj := interactiveSeverityRank(maxSevByID[rows[j].id])
		if si != sj {
			return si < sj
		}
		if rows[i].relationship != rows[j].relationship {
			return interactiveRelationshipOrder(rows[i].relationship) < interactiveRelationshipOrder(rows[j].relationship)
		}
		return rows[i].id < rows[j].id
	})

	items := make([]interactiveListItem, 0, len(rows))
	for _, row := range rows {
		badges := interactivePackageBadges(row)
		if sev := maxSevByID[row.id]; sev != "" {
			// Prepend the severity badge so it appears before the scope badge.
			badges = append([]interactiveBadge{{label: sev, kind: "severity-" + strings.ToLower(sev)}}, badges...)
		}
		items = append(items, interactiveListItem{
			title:    row.displayName,
			subtitle: row.relationship,
			badges:   badges,
			details:  interactiveComponentDetails(m.graphValue, row, manifest, m.findings),
		})
	}

	navigationHelp := interactiveCommonNavigationHelp
	if m.allowManifestExit {
		navigationHelp += "; Backspace/Left/h returns to manifests"
	}

	return &interactiveListModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: []string{
			ansiStyled("Tab: [PACKAGES] | Vulnerabilities | Licenses", ansiDim),
			ansiStyled("Manifest  ", ansiDim) + manifest.displayName,
			ansiStyled("Root      ", ansiDim) + interactivePackageDisplayName(rootPkg),
			ansiStyled("Filter relationship ", ansiDim) + valueOrDash(m.relationshipFilter),
			ansiStyled("Filter scope ", ansiDim) + valueOrDash(m.scopeFilter),
			ansiStyled("Filter severity ", ansiDim) + valueOrDash(m.severityFilter),
			ansiStyled(fmt.Sprintf("Direct    %d", len(groups.direct)), ansiCyan, ansiBold),
			ansiStyled(fmt.Sprintf("Transitive %d", len(groups.transitive)), ansiCyan, ansiBold),
			ansiStyled("Project   ", ansiDim) + m.project.Path,
		},
		navigationHelp: navigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; r cycles relationship filter; s cycles scope filter; v cycles severity filter",
		emptyState:     "No components were found for this manifest.",
		items:          items,
	}
}

func (m *interactiveScanModel) buildExplainComponentListModel(manifest interactiveListPackageRow) *interactiveListModel {
	labels, counts := interactiveExplainRelationships(m.graphValue, manifest.targetID)
	rows := make([]interactiveListPackageRow, 0, len(labels))
	if m.graphValue != nil {
		for _, pkg := range m.graphValue.Packages() {
			if pkg == nil {
				continue
			}
			row := interactivePackageRowFromGraph(pkg, labels[pkg.ID])
			row.targetID = manifest.targetID
			rows = append(rows, row)
		}
	}
	rows = filterInteractivePackageRows(rows, m.relationshipFilter, m.scopeFilter)
	maxSevByID := interactiveMaxSeverityByPkgID(m.findings)
	if m.severityFilter != "" {
		kept := rows[:0]
		for _, row := range rows {
			if strings.EqualFold(maxSevByID[row.id], m.severityFilter) {
				kept = append(kept, row)
			}
		}
		rows = kept
	}
	sort.Slice(rows, func(i, j int) bool {
		si := interactiveSeverityRank(maxSevByID[rows[i].id])
		sj := interactiveSeverityRank(maxSevByID[rows[j].id])
		if si != sj {
			return si < sj
		}
		if rows[i].relationship != rows[j].relationship {
			return interactiveRelationshipOrder(rows[i].relationship) < interactiveRelationshipOrder(rows[j].relationship)
		}
		return rows[i].id < rows[j].id
	})
	items := make([]interactiveListItem, 0, len(rows))
	for _, row := range rows {
		badges := interactivePackageBadges(row)
		if sev := maxSevByID[row.id]; sev != "" {
			badges = append([]interactiveBadge{{label: sev, kind: "severity-" + strings.ToLower(sev)}}, badges...)
		}
		items = append(items, interactiveListItem{
			title:    row.displayName,
			subtitle: row.relationship,
			badges:   badges,
			details:  interactiveComponentDetails(m.graphValue, row, manifest, m.findings),
		})
	}
	targetPkg, _ := m.graphValue.Package(manifest.targetID)
	return &interactiveListModel{
		title: fmt.Sprintf("%s: %s", m.titlePrefix, m.project.Name),
		summary: []string{
			ansiStyled("Tab: [PACKAGES] | Vulnerabilities | Licenses", ansiDim),
			ansiStyled("Manifest  ", ansiDim) + manifest.displayName,
			ansiStyled("Target    ", ansiDim) + interactivePackageDisplayName(targetPkg),
			ansiStyled("Filter relationship ", ansiDim) + valueOrDash(m.relationshipFilter),
			ansiStyled("Filter scope ", ansiDim) + valueOrDash(m.scopeFilter),
			ansiStyled("Filter severity ", ansiDim) + valueOrDash(m.severityFilter),
			ansiStyled(fmt.Sprintf("Self      %d", counts["self"]), ansiCyan, ansiBold),
			ansiStyled(fmt.Sprintf("Parents   %d", counts["parent"]), ansiCyan, ansiBold),
			ansiStyled(fmt.Sprintf("Ancestors %d", counts["ancestor"]), ansiCyan, ansiBold),
			ansiStyled(fmt.Sprintf("Roots     %d", counts["root"]), ansiCyan, ansiBold),
			ansiStyled("Project   ", ansiDim) + m.project.Path,
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; Enter keeps selection; Esc clears search; r cycles relationship filter; s cycles scope filter; v cycles severity filter",
		emptyState:     "No components were found for this explanation.",
		items:          items,
	}
}

func interactiveManifestIDFromTitle(value string) string {
	start := strings.LastIndex(value, "[")
	end := strings.LastIndex(value, "]")
	if start == -1 || end == -1 || end <= start+1 {
		return ""
	}
	return strings.TrimSpace(value[start+1 : end])
}

func interactiveManifestRows(consolidated model.ConsolidatedGraph) []interactiveListPackageRow {
	if len(consolidated.Manifests) == 0 {
		return nil
	}

	rows := make([]interactiveListPackageRow, 0, len(consolidated.Manifests))
	for idx, manifest := range consolidated.Manifests {
		manifestID := strings.TrimSpace(manifest.Entry.Manifest.Path)
		if manifestID == "" {
			manifestID = fmt.Sprintf("manifest-%d", idx+1)
		}

		manifestName := filepath.Base(strings.ReplaceAll(manifestID, "\\", "/"))
		if manifestName == "" {
			manifestName = manifestID
		}

		rootID := ""
		if strings.TrimSpace(manifest.RootManifestID) != "" {
			rootID = manifest.RootManifestID
		} else if manifest.Entry.Graph != nil {
			roots := manifest.Entry.Graph.Roots()
			if len(roots) > 0 && roots[0] != nil {
				rootID = roots[0].ID
			}
		}

		rows = append(rows, interactiveListPackageRow{
			id:           manifestID,
			rootID:       rootID,
			targetID:     interactiveManifestTargetID(manifest.Entry.Graph),
			displayName:  manifestName,
			relationship: "manifest",
		})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	return rows
}

func interactiveManifestDetails(graphValue *model.Graph, row interactiveListPackageRow) []string {
	groups := interactiveRootDependencies(graphValue, row.rootID)
	rootPkg, _ := graphValue.Package(row.rootID)
	lines := []string{
		ansiStyled("Manifest", ansiBold, ansiCyan),
		ansiStyled("  Name: ", ansiDim) + row.displayName,
		ansiStyled("  ID: ", ansiDim) + valueOrDash(row.id),
		ansiStyled("  Kind: ", ansiDim) + valueOrDash(filepath.Base(row.id)),
		ansiStyled("  Type: ", ansiDim) + interactiveStatusText(row.relationship),
		"",
		ansiStyled("Dependencies", ansiBold, ansiMagenta),
		ansiStyled("  Root (project package): ", ansiDim) + interactivePackageDisplayName(rootPkg),
		ansiStyled("  Direct dependencies: ", ansiDim) + fmt.Sprintf("%d", len(groups.direct)),
		ansiStyled("  Transitive dependencies: ", ansiDim) + fmt.Sprintf("%d", len(groups.transitive)),
		"",
		ansiStyled("Press Enter to view components for this manifest.", ansiDim),
		"",
	}
	return lines
}

func interactiveManifestTargetID(graphValue *model.Graph) string {
	if graphValue == nil {
		return ""
	}
	leaves := make([]string, 0)
	for _, pkg := range graphValue.Packages() {
		if pkg == nil {
			continue
		}
		deps, err := graphValue.Dependencies(pkg.ID)
		if err == nil && len(deps) == 0 {
			leaves = append(leaves, pkg.ID)
		}
	}
	if len(leaves) == 0 {
		return ""
	}
	sort.Strings(leaves)
	return leaves[0]
}

func interactivePackageRowFromGraph(pkg *model.Package, relationship string) interactiveListPackageRow {
	if pkg == nil {
		return interactiveListPackageRow{relationship: relationship}
	}
	name := pkg.DisplayName()
	displayName := name
	if pkg.Version != "" {
		displayName = name + "@" + pkg.Version
	}
	return interactiveListPackageRow{
		id:           pkg.ID,
		rootID:       pkg.ID,
		displayName:  displayName,
		version:      pkg.Version,
		scope:        pkg.Scope,
		relationship: relationship,
		purl:         pkg.PURL,
	}
}

func interactivePackageDisplayName(pkg *model.Package) string {
	if pkg == nil {
		return "-"
	}
	name := pkg.DisplayName()
	if pkg.Version != "" {
		name += "@" + pkg.Version
	}
	if pkg.Scope != "" {
		name += " [" + pkg.Scope + "]"
	}
	return name
}

func interactiveComponentBaseName(value string) string {
	if idx := strings.LastIndex(value, " ["); idx >= 0 && strings.HasSuffix(value, "]") {
		return value[:idx]
	}
	return value
}

func interactiveComponentDetails(graphValue *model.Graph, row interactiveListPackageRow, manifest interactiveListPackageRow, findings []model.Finding) []string {
	lines := []string{
		ansiStyled("Component", ansiBold, ansiCyan),
		ansiStyled("  Manifest: ", ansiDim) + manifest.displayName,
		ansiStyled("  Name: ", ansiDim) + interactiveComponentBaseName(row.displayName),
		ansiStyled("  ID: ", ansiDim) + valueOrDash(row.id),
		ansiStyled("  Version: ", ansiDim) + valueOrDash(row.version),
		ansiStyled("  Scope: ", ansiDim) + valueOrDash(row.scope),
		ansiStyled("  Relationship: ", ansiDim) + interactiveStatusText(row.relationship),
		ansiStyled("  PURL: ", ansiDim) + valueOrDash(row.purl),
		"",
	}

	appendPackages := func(title string, packages []*model.Package) {
		lines = append(lines, ansiStyled(title, ansiBold, ansiMagenta))
		if len(packages) == 0 {
			lines = append(lines, ansiStyled("  (none)", ansiDim))
			lines = append(lines, "")
			return
		}
		for _, pkg := range packages {
			value := pkg.DisplayName()
			if pkg.Version != "" {
				value += "@" + pkg.Version
			}
			if pkg.Scope != "" {
				value += " [" + pkg.Scope + "]"
			}
			lines = append(lines, ansiStyled("  - ", ansiDim)+value)
		}
		lines = append(lines, "")
	}

	if graphValue != nil {
		deps, _ := graphValue.Dependencies(row.id)
		appendPackages("Dependencies", deps)
		dependents, _ := graphValue.Dependents(row.id)
		appendPackages("Dependents", dependents)
	}

	// Vulnerabilities section
	lines = append(lines, ansiStyled("Vulnerabilities", ansiBold, ansiCyan))
	var pkgFindings []model.Finding
	for _, f := range findings {
		if f.Kind == model.FindingKindVulnerability && f.Package != nil && f.Package.ID == row.id {
			pkgFindings = append(pkgFindings, f)
		}
	}
	if len(pkgFindings) == 0 {
		lines = append(lines, ansiStyled("  (none)", ansiDim))
	} else {
		for _, f := range pkgFindings {
			var severityLabel string
			switch strings.ToLower(f.Severity) {
			case "critical":
				severityLabel = ansiStyled(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", ansiBgRed, ansiWhite, ansiBold)
			case "high":
				severityLabel = ansiStyled(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", ansiBgRed, ansiWhite)
			case "medium":
				severityLabel = ansiStyled(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", ansiBgYellow, ansiBold)
			case "low":
				severityLabel = ansiStyled(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", ansiBgCyan, ansiBlue, ansiBold)
			default:
				severityLabel = ansiStyled(" "+strings.ToUpper(valueOrDash(f.Severity))+" ", ansiDim)
			}
			title := valueOrDash(f.Title)
			if title == "-" {
				title = ""
			} else {
				title = " " + title
			}
			lines = append(lines, "  "+severityLabel+" "+ansiStyled(f.ID, ansiBold)+title)
		}
	}
	lines = append(lines, "")

	// Licenses section
	lines = append(lines, ansiStyled("Licenses", ansiBold, ansiCyan))
	var pkg *model.Package
	if graphValue != nil {
		pkg, _ = graphValue.Package(row.id)
	}
	if pkg == nil || len(pkg.Licenses) == 0 {
		lines = append(lines, ansiStyled("  (none)", ansiDim))
	} else {
		for _, lic := range pkg.Licenses {
			expr := lic.SPDXExpression
			if expr == "" {
				expr = lic.Value
			}
			if lic.Type != "" {
				expr += " [" + lic.Type + "]"
			}
			lines = append(lines, ansiStyled("  - ", ansiDim)+valueOrDash(expr))
		}
	}
	lines = append(lines, "")

	return lines
}

func interactiveRootDependencies(graphValue *model.Graph, rootID string) interactiveRootDependencyGroup {
	if graphValue == nil || strings.TrimSpace(rootID) == "" {
		return interactiveRootDependencyGroup{}
	}

	direct, err := graphValue.Dependencies(rootID)
	if err != nil || len(direct) == 0 {
		return interactiveRootDependencyGroup{}
	}

	directByID := make(map[string]*model.Package, len(direct))
	for _, pkg := range direct {
		directByID[pkg.ID] = pkg
	}

	transitiveByID := make(map[string]*model.Package)
	visited := make(map[string]struct{}, len(direct)+1)
	queue := make([]string, 0, len(direct))
	visited[rootID] = struct{}{}
	for _, pkg := range direct {
		queue = append(queue, pkg.ID)
		visited[pkg.ID] = struct{}{}
	}

	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]
		dependencies, depErr := graphValue.Dependencies(currentID)
		if depErr != nil {
			continue
		}
		for _, dependency := range dependencies {
			if dependency == nil || dependency.ID == rootID {
				continue
			}
			if _, isDirect := directByID[dependency.ID]; !isDirect {
				if _, exists := transitiveByID[dependency.ID]; !exists {
					transitiveByID[dependency.ID] = dependency
				}
			}
			if _, seen := visited[dependency.ID]; seen {
				continue
			}
			visited[dependency.ID] = struct{}{}
			queue = append(queue, dependency.ID)
		}
	}

	transitive := make([]*model.Package, 0, len(transitiveByID))
	for _, pkg := range transitiveByID {
		transitive = append(transitive, pkg)
	}
	sort.Slice(direct, func(i, j int) bool {
		return interactivePackageSortKey(direct[i]) < interactivePackageSortKey(direct[j])
	})
	sort.Slice(transitive, func(i, j int) bool {
		return interactivePackageSortKey(transitive[i]) < interactivePackageSortKey(transitive[j])
	})

	return interactiveRootDependencyGroup{direct: direct, transitive: transitive}
}

func interactivePackageSortKey(pkg *model.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.ID + "\x00" + pkg.DisplayName() + "\x00" + pkg.Version
}
