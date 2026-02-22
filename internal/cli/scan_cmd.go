package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/output"
	"github.com/bomly/bomly-cli/internal/sbom"
	"github.com/bomly/bomly-cli/internal/scan"
	"github.com/bomly/bomly-cli/internal/viewmodel"
	"github.com/spf13/cobra"
)

type sbomOutputSpec struct {
	target sbom.Target
	label  string
	path   string
}

func newScanCmd(options *globalOptions) *cobra.Command {
	var outputs []string
	var scopeValue string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan dependencies and render a graph or SBOM",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			started := time.Now()
			current := options.current()
			logger := commandLogger(cmd, options, "scan")
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			progress := newCommandProgress(streams, "Resolving dependencies")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if progress != nil {
					progress.Fail("Scan aborted")
				}
				restoreStdout()
			}()
			ctx, err := options.newCommandContext(logger)
			if err != nil {
				return err
			}
			defer func() { _ = ctx.close() }()

			graphOutputFormat := ctx.format
			if graphOutputFormat == output.FormatSARIF && !ctx.config.Audit {
				return invalidInputf("--format sarif requires --audit")
			}
			selectedScope, err := scan.ParseScope(scopeValue)
			if err != nil {
				return invalidInputf("%v", err)
			}

			var outputSpecs []sbomOutputSpec
			if len(outputs) > 0 {
				outputSpecs, err = parseSBOMOutputSpecs(outputs)
				if err != nil {
					return invalidInputf("%v", err)
				}
			}

			pipeline := newPipeline(ctx, logger)
			pipeReq := pipelineRequest(ctx, selectedScope, streams.notificationWriter())
			pipeResult, err := pipeline.Run(cmd.Context(), pipeReq)
			if err != nil {
				return resolutionFailure(err)
			}
			resolved := pipeResult.ResolveResults
			subprojectChildren := subprojectProgressChildren(resolved)
			subprojectChildren = append(subprojectChildren, warningProgressChildren(pipeResult.DetectorWarnings)...)
			progress.CompleteStep("Indexed subprojects", subprojectChildren)
			progress.CompleteStep("Detected Dependencies", detectorProgressChildren(resolved))
			if len(pipeResult.MatcherRuns) > 0 || len(pipeResult.MatchWarnings) > 0 {
				progress.CompleteStep("Enriched packages", matchProgressChildren(pipeResult.Graph, pipeResult.MatcherRuns, pipeResult.MatchWarnings))
			}

			consolidated := pipeResult.Consolidated
			selectedGraph := pipeResult.Graph

			if len(outputSpecs) > 0 {
				progress.Advance("Writing SBOM output")
				stdout := streams.reportWriter()
				for _, spec := range outputSpecs {
					rawDocument, err := sbom.MarshalDepGraphJSON(selectedGraph, spec.target, sbom.BuildOptions{}, sbom.EncodeOptions{Pretty: true})
					if err != nil {
						return fmt.Errorf("marshal %s sbom: %w", spec.label, err)
					}
					if err := writeSBOMDocument(stdout, spec, rawDocument); err != nil {
						return err
					}
				}
				if !ctx.config.Interactive {
					progress.Success("Wrote SBOM output")
					return nil
				}
			}

			var enrichResult auditEnrichResult
			if ctx.config.Audit {
				enrichResult.Findings = deduplicateFindings(pipeResult.Findings)
				progress.CompleteStep("Evaluated policy", auditProgressChildren(pipeResult.AuditorRuns, pipeResult.AuditorFindings, pipeResult.AuditWarnings))
			}
			payload := viewmodel.BuildScanResponse(ctx.projectDescriptor(), consolidated, enrichResult.Findings, started)

			if graphOutputFormat == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), enrichResult.Findings, "bomly", cmd.Root().Version)
			}

			if ctx.config.Interactive {
				progress.Success("Resolved Graph")
				return runInteractiveModel(cmd.InOrStdin(), streams.interactiveWriter(), newScanInteractiveModel(payload.Project, consolidated, selectedGraph, enrichResult.Findings))
			}

			writer, closeWriter, err := ctx.writer(streams.reportWriter())
			if err != nil {
				return err
			}
			defer func() { _ = closeWriter() }()
			progress.Success("Resolved Graph")
			if ctx.format == output.FormatText {
				progress.SeparateReport()
			}

			err = output.Write(writer, ctx.format, payload, output.Renderers{
				Text: func(w io.Writer) error {
					if len(resolved) == 1 {
						if _, err := fmt.Fprintf(w, "Dependency report for %s\n\n", scanGraphDisplayName(selectedGraph, payload.Project.Name)); err != nil {
							return err
						}
					} else {
						if _, err := fmt.Fprintf(w, "Dependency report for %d subprojects\n\n", len(resolved)); err != nil {
							return err
						}
					}
					_, err := io.WriteString(w, renderScanReport(payload.Manifests, selectedGraph, enrichResult.Findings, ctx.config.Enrich, ctx.config.Audit))
					return err
				},
			})
			if err == nil && ctx.config.Audit && len(enrichResult.Findings) > 0 {
				return policyViolationFindings(len(enrichResult.Findings))
			}
			return err
		},
	}
	cmd.Flags().StringArrayVarP(&outputs, "sbom-output", "o", nil, "SBOM output target as <format> or <format>=<path>; repeat for multiple outputs")
	cmd.Flags().StringVar(&scopeValue, "scope", "", "Filter dependencies by scope: runtime or development")
	return cmd
}

func filterResolvedGraphsByScope(results []scan.ResolveGraphResult, selectedScope scan.Scope) ([]scan.ResolveGraphResult, error) {
	if selectedScope == scan.ScopeUnknown {
		return results, nil
	}

	filtered := make([]scan.ResolveGraphResult, 0, len(results))
	for _, result := range results {
		if result.Graphs == nil {
			filtered = append(filtered, result)
			continue
		}
		entries := make([]scan.GraphEntry, 0, len(result.Graphs.Entries))
		for _, entry := range result.Graphs.Entries {
			if entry.Graph == nil {
				entries = append(entries, entry)
				continue
			}
			graphView, err := scan.FilterGraphByScope(entry.Graph, selectedScope)
			if err != nil {
				return nil, err
			}
			entries = append(entries, scan.GraphEntry{
				Graph:    graphView,
				Manifest: entry.Manifest,
			})
		}
		result.Graphs = &scan.GraphContainer{Entries: entries}
		filtered = append(filtered, result)
	}
	return filtered, nil
}

func scanGraphDisplayName(g *model.Graph, fallback string) string {
	if g == nil {
		return fallback
	}
	roots := g.Roots()
	if len(roots) != 1 {
		return fallback
	}
	if roots[0].QualifiedName() != "" {
		return roots[0].QualifiedName()
	}
	if roots[0].ID != "" {
		return roots[0].ID
	}
	return fallback
}

func renderScanReport(manifests []viewmodel.ScanManifest, g *model.Graph, findings []scan.Finding, enrichEnabled, auditEnabled bool) string {
	var b strings.Builder

	if g == nil {
		return "(empty graph)"
	}

	summary := viewmodel.SummaryFromFindings(findings)
	roots, direct, transitive := scanRelationshipCounts(g)
	runtimeCount, developmentCount, unknownScopeCount := scanScopeCounts(g)
	fmt.Fprintf(&b, "Executive Summary\n")
	fmt.Fprintf(&b, "  Packages: %d total\n", g.Size())
	fmt.Fprintf(&b, "  Relationships: %d root, %d direct, %d transitive\n", roots, direct, transitive)
	fmt.Fprintf(&b, "  Scopes: %d runtime, %d development, %d unspecified\n", runtimeCount, developmentCount, unknownScopeCount)
	fmt.Fprintf(&b, "  Vulnerability enrichment: %s\n", formatEnrichmentSummary(g, enrichEnabled))
	fmt.Fprintf(&b, "  Policy findings: %s\n", formatAuditSummary(summary, auditEnabled))
	fmt.Fprintf(&b, "  Unique licenses: %d\n", scanUniqueLicenseCount(g))

	b.WriteString("\nManifests\n")
	b.WriteString(renderScanManifestTable(manifests))

	b.WriteString("\nDependency Inventory\n")
	b.WriteString(renderScanGraphTable(g))

	b.WriteString("\n\nPolicy Findings\n")
	if len(findings) == 0 {
		if auditEnabled {
			b.WriteString("No policy findings.\n")
		} else {
			b.WriteString("Policy evaluation not enabled. Run with --audit to create findings.\n")
		}
	} else {
		sorted := make([]scan.Finding, len(findings))
		copy(sorted, findings)
		sort.Slice(sorted, func(i, j int) bool {
			si := severityRankTable(sorted[i].Severity)
			sj := severityRankTable(sorted[j].Severity)
			if si != sj {
				return si < sj
			}
			if sorted[i].ID != sorted[j].ID {
				return sorted[i].ID < sorted[j].ID
			}
			pkgI, pkgJ := "", ""
			if sorted[i].Package != nil {
				pkgI = sorted[i].Package.DisplayName()
			}
			if sorted[j].Package != nil {
				pkgJ = sorted[j].Package.DisplayName()
			}
			return pkgI < pkgJ
		})
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "SEVERITY\tID\tPACKAGE\tTITLE\tSOURCE")
		for _, f := range sorted {
			pkgName := "-"
			if f.Package != nil {
				pkgName = f.Package.DisplayName()
				if f.Package.Version != "" {
					pkgName += "@" + f.Package.Version
				}
			}
			title := f.Title
			if title == "" {
				title = f.ID
			}
			if len(title) > 60 {
				title = title[:57] + "..."
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
				f.Severity, f.ID, pkgName, title, f.Source)
		}
		_ = tw.Flush()
	}

	b.WriteString("\nLicense Overview\n")
	b.WriteString(renderUniqueLicensesTable(g))

	report := strings.TrimRight(b.String(), "\n")
	return report
}

func severityRankTable(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func renderUniqueLicensesTable(g *model.Graph) string {
	if g == nil || g.Size() == 0 {
		return "(no packages)\n"
	}

	type licenseSummaryRow struct {
		identifier string
		spdx       string
		value      string
		sourceType string
		packages   map[string]struct{}
	}
	rowsByIdentifier := make(map[string]*licenseSummaryRow)
	for _, pkg := range g.Packages() {
		if pkg == nil {
			continue
		}
		for _, license := range pkg.Licenses {
			identifier := graphLicenseIdentifier(license)
			if identifier == "" {
				continue
			}
			row, ok := rowsByIdentifier[identifier]
			if !ok {
				row = &licenseSummaryRow{
					identifier: identifier,
					packages:   make(map[string]struct{}),
				}
				rowsByIdentifier[identifier] = row
			}
			if row.spdx == "" {
				row.spdx = strings.TrimSpace(license.SPDXExpression)
			}
			if row.value == "" {
				row.value = strings.TrimSpace(license.Value)
			}
			if row.sourceType == "" {
				row.sourceType = strings.TrimSpace(license.Type)
			}
			row.packages[pkg.ID] = struct{}{}
		}
	}
	if len(rowsByIdentifier) == 0 {
		return "(no license information available)\n"
	}

	rows := make([]licenseSummaryRow, 0, len(rowsByIdentifier))
	for _, row := range rowsByIdentifier {
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].identifier != rows[j].identifier {
			return rows[i].identifier < rows[j].identifier
		}
		if len(rows[i].packages) != len(rows[j].packages) {
			return len(rows[i].packages) > len(rows[j].packages)
		}
		return rows[i].sourceType < rows[j].sourceType
	})
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "IDENTIFIER\tSPDX\tVALUE\tSOURCE\tPACKAGES")
	for _, row := range rows {
		_, _ = fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%d\n",
			valueOrDash(row.identifier),
			valueOrDash(row.spdx),
			valueOrDash(row.value),
			valueOrDash(row.sourceType),
			len(row.packages),
		)
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func formatAuditSummary(summary *viewmodel.AuditSummary, auditEnabled bool) string {
	if summary == nil || summary.Total == 0 {
		if auditEnabled {
			return "none"
		}
		return "not audited"
	}
	parts := make([]string, 0, 5)
	if summary.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", summary.Critical))
	}
	if summary.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", summary.High))
	}
	if summary.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", summary.Medium))
	}
	if summary.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", summary.Low))
	}
	if summary.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", summary.Unknown))
	}
	return fmt.Sprintf("%d total (%s)", summary.Total, strings.Join(parts, ", "))
}

func formatEnrichmentSummary(g *model.Graph, enrichEnabled bool) string {
	if g == nil || g.Size() == 0 {
		if !enrichEnabled {
			return "disabled"
		}
		return "enabled"
	}
	packagesWithVulnerabilities := 0
	totalVulnerabilities := 0
	for _, pkg := range g.Packages() {
		if pkg == nil || len(pkg.Vulnerabilities) == 0 {
			continue
		}
		packagesWithVulnerabilities++
		totalVulnerabilities += len(pkg.Vulnerabilities)
	}
	if !enrichEnabled {
		if totalVulnerabilities > 0 {
			return fmt.Sprintf("%d matched across %d packages (present from existing package data)", totalVulnerabilities, packagesWithVulnerabilities)
		}
		return "disabled"
	}
	if totalVulnerabilities == 0 {
		return "enabled (no matched vulnerabilities)"
	}
	return fmt.Sprintf("%d matched across %d packages", totalVulnerabilities, packagesWithVulnerabilities)
}

func renderScanManifestTable(manifests []viewmodel.ScanManifest) string {
	if len(manifests) == 0 {
		return "(no manifests)\n"
	}

	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SUBPROJECT\tMANIFEST\tKIND\tMANAGER\tPACKAGES")
	for _, manifest := range manifests {
		subproject := manifest.Subproject
		if subproject == "" {
			subproject = "."
		}
		pathValue := manifest.Path
		if pathValue == "" {
			pathValue = "-"
		}
		kind := manifest.Kind
		if kind == "" {
			kind = "-"
		}
		manager := manifest.PackageManager
		if manager == "" {
			manager = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", subproject, pathValue, kind, manager, len(manifest.Packages))
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func scanRelationshipCounts(g *model.Graph) (roots, direct, transitive int) {
	if g == nil {
		return 0, 0, 0
	}
	rootIDs := make(map[string]struct{})
	for _, root := range g.Roots() {
		if root != nil {
			rootIDs[root.ID] = struct{}{}
			roots++
		}
	}
	for _, pkg := range g.Packages() {
		if pkg == nil {
			continue
		}
		if _, isRoot := rootIDs[pkg.ID]; isRoot {
			continue
		}
		dependents, err := g.Dependents(pkg.ID)
		if err != nil {
			continue
		}
		isDirect := false
		for _, dependent := range dependents {
			if dependent != nil {
				if _, isRoot := rootIDs[dependent.ID]; isRoot {
					isDirect = true
					break
				}
			}
		}
		if isDirect {
			direct++
		} else {
			transitive++
		}
	}
	return roots, direct, transitive
}

func scanScopeCounts(g *model.Graph) (runtimeCount, developmentCount, unknownCount int) {
	if g == nil {
		return 0, 0, 0
	}
	for _, pkg := range g.Packages() {
		if pkg == nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(pkg.Scope)) {
		case string(scan.ScopeRuntime):
			runtimeCount++
		case string(scan.ScopeDevelopment):
			developmentCount++
		default:
			unknownCount++
		}
	}
	return runtimeCount, developmentCount, unknownCount
}

func scanUniqueLicenseCount(g *model.Graph) int {
	if g == nil {
		return 0
	}
	licenseSet := make(map[string]struct{})
	for _, pkg := range g.Packages() {
		for _, value := range pkg.LicenseValues() {
			licenseSet[value] = struct{}{}
		}
	}
	return len(licenseSet)
}

func renderScanGraphTable(g *model.Graph) string {
	if g == nil || g.Size() == 0 {
		return "(empty graph)"
	}

	rootIDs := make(map[string]struct{})
	for _, root := range g.Roots() {
		rootIDs[root.ID] = struct{}{}
	}

	type row struct {
		name         string
		version      string
		scope        string
		relationship string
		licenses     string
		id           string
	}

	rows := make([]row, 0, g.Size())
	for _, pkg := range g.Packages() {
		relationship := "transitive"
		if _, isRoot := rootIDs[pkg.ID]; isRoot {
			relationship = "root"
		} else if dependents, err := g.Dependents(pkg.ID); err == nil {
			for _, dependent := range dependents {
				if _, isRoot := rootIDs[dependent.ID]; isRoot {
					relationship = "direct"
					break
				}
			}
		}

		rows = append(rows, row{
			name:         pkg.DisplayName(),
			version:      pkg.Version,
			scope:        pkg.Scope,
			relationship: relationship,
			licenses:     packageLicenseIdentifiers(pkg),
			id:           pkg.ID,
		})
	}

	if len(rows) == 0 {
		return "(no dependencies)"
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].relationship != rows[j].relationship {
			return interactiveRelationshipOrder(rows[i].relationship) < interactiveRelationshipOrder(rows[j].relationship)
		}
		return rows[i].id < rows[j].id
	})

	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PACKAGE\tVERSION\tSCOPE\tRELATIONSHIP\tLICENSES")
	for _, row := range rows {
		version := row.version
		if version == "" {
			version = "-"
		}
		scope := row.scope
		if scope == "" {
			scope = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", row.name, version, scope, row.relationship, valueOrDash(row.licenses))
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}

func packageLicenseIdentifiers(pkg *model.Package) string {
	if pkg == nil || len(pkg.Licenses) == 0 {
		return ""
	}
	values := make([]string, 0, len(pkg.Licenses))
	for _, license := range pkg.Licenses {
		if identifier := graphLicenseIdentifier(license); identifier != "" {
			values = append(values, identifier)
		}
	}
	if len(values) == 0 {
		return ""
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func graphLicenseIdentifier(license model.PackageLicense) string {
	switch {
	case strings.TrimSpace(license.SPDXExpression) != "":
		return strings.TrimSpace(license.SPDXExpression)
	case strings.TrimSpace(license.Value) != "":
		return strings.TrimSpace(license.Value)
	default:
		return ""
	}
}

func parseSBOMFormat(value string) (sbom.Target, string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "spdx-json":
		return sbom.TargetSPDX23JSON, "spdx-json", nil
	case "cyclonedx-json":
		return sbom.TargetCycloneDX16JSON, "cyclonedx-json", nil
	default:
		return "", "", fmt.Errorf("unsupported sbom format %q", value)
	}
}

func parseSBOMOutputSpecs(values []string) ([]sbomOutputSpec, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one -o <format>[=<path>] output is required")
	}

	specs := make([]sbomOutputSpec, 0, len(values))
	stdoutCount := 0
	for _, value := range values {
		rawValue := strings.TrimSpace(value)
		if rawValue == "" {
			return nil, fmt.Errorf("sbom output cannot be empty")
		}

		formatValue, pathValue, hasPath := strings.Cut(rawValue, "=")
		target, label, err := parseSBOMFormat(formatValue)
		if err != nil {
			return nil, err
		}

		spec := sbomOutputSpec{target: target, label: label}
		if hasPath {
			spec.path = strings.TrimSpace(pathValue)
			if spec.path == "" {
				return nil, fmt.Errorf("sbom output %q is missing a file path", rawValue)
			}
		} else {
			stdoutCount++
		}
		specs = append(specs, spec)
	}

	if stdoutCount > 1 {
		return nil, fmt.Errorf("multiple stdout sbom outputs are not supported")
	}

	return specs, nil
}

func writeSBOMDocument(stdout io.Writer, spec sbomOutputSpec, document []byte) error {
	if spec.path == "" {
		if _, err := stdout.Write(document); err != nil {
			return fmt.Errorf("write %s sbom to stdout: %w", spec.label, err)
		}
		if _, err := io.WriteString(stdout, "\n"); err != nil {
			return fmt.Errorf("terminate %s sbom output: %w", spec.label, err)
		}
		return nil
	}

	if err := os.WriteFile(spec.path, append(document, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s sbom to %s: %w", spec.label, spec.path, err)
	}
	return nil
}
