package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	gitutil "github.com/bomly/bomly-cli/internal/git"
	"github.com/bomly/bomly-cli/internal/output"
	"github.com/bomly/bomly-cli/internal/registry"
	"github.com/bomly/bomly-cli/internal/scan"
	"github.com/bomly/bomly-cli/internal/system"
	"github.com/bomly/bomly-cli/internal/viewmodel"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type diffResolvedTarget struct {
	Context  commandContext
	Results  []scan.ResolveGraphResult
	Warnings []scan.PipelineWarning
}

func (t diffResolvedTarget) close() error {
	return t.Context.close()
}

func newDiffCmd(options *globalOptions) *cobra.Command {
	var baseRef string
	var headRef string

	cmd := &cobra.Command{
		Use:   "diff --base <ref> --head <ref>",
		Short: "Compare dependency states",
		Long:  "Compare dependency states between two git refs or two container image tags/digests.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := commandLogger(cmd, options, "diff")
			current := options.current()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			progress := newCommandProgress(streams, "Resolving diff inputs")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if progress != nil {
					progress.Fail("Diff aborted")
				}
				restoreStdout()
			}()
			if options.Ref != "" {
				return invalidInputf("diff does not support --ref; use --base and --head")
			}

			// Validate SBOM diff mode vs git diff mode flag combinations.
			if current.SBOM {
				if baseRef == "" {
					return invalidInputf("--base is required when --sbom is set")
				}
				if headRef == "" {
					return invalidInputf("--head is required when --sbom is set")
				}
				if options.Container != "" {
					return invalidInputf("--sbom cannot be combined with --container")
				}
			} else {
				if baseRef == "" {
					return invalidInputf("--base is required (or use --sbom to treat refs as SBOM file paths)")
				}
				if headRef == "" {
					return invalidInputf("--head is required (or use --sbom to treat refs as SBOM file paths)")
				}
			}

			started := time.Now()
			outputFormat, err := parseOutputMode(current)
			if err != nil {
				return invalidInputf("%v", err)
			}
			if outputFormat == output.FormatSARIF && !current.Audit {
				return invalidInputf("--format sarif requires --audit")
			}

			var baseTarget diffResolvedTarget
			var headTarget diffResolvedTarget
			projectIdentifier := ""
			compBase := baseRef
			compHead := headRef
			var resolutionWarnings []scan.PipelineWarning

			switch {
			case current.SBOM:
				baseTarget, headTarget, projectIdentifier, resolutionWarnings, err = resolveSBOMDiffGraphs(options, logger, baseRef, headRef, streams.notificationWriter())
			case options.Container != "":
				baseTarget, headTarget, projectIdentifier, resolutionWarnings, err = resolveContainerDiffGraphs(options, logger, baseRef, headRef, streams.notificationWriter())
			default:
				baseTarget, headTarget, projectIdentifier, resolutionWarnings, err = resolveGitDiffGraphs(options, logger, baseRef, headRef, streams.notificationWriter())
			}
			if err != nil {
				return err
			}
			defer func() { _ = baseTarget.close() }()
			defer func() { _ = headTarget.close() }()

			baseResults := baseTarget.Results
			headResults := headTarget.Results
			allResults := append(append([]scan.ResolveGraphResult{}, baseResults...), headResults...)
			subprojectChildren := subprojectProgressChildren(allResults)
			subprojectChildren = append(subprojectChildren, warningProgressChildren(resolutionWarnings)...)
			progress.CompleteStep("Indexed subprojects", subprojectChildren)
			progress.CompleteStep("Detected Dependencies", detectorProgressChildren(allResults))
			if current.Audit {
				progress.Advance("Finding licenses")
				baseResults = enrichResolvedGraphs(baseTarget.Context, logger, baseResults, streams.notificationWriter())
				headResults = enrichResolvedGraphs(headTarget.Context, logger, headResults, streams.notificationWriter())
				allEnriched := append(append([]scan.ResolveGraphResult{}, baseResults...), headResults...)
				progress.CompleteStep("Found Licenses", licenseProgressChildren(allEnriched))
				progress.Advance("Auditing diff targets")
			}

			baseConsolidated, err := scan.ConsolidateGraphs(baseResults)
			if err != nil {
				return resolutionFailure(err)
			}
			headConsolidated, err := scan.ConsolidateGraphs(headResults)
			if err != nil {
				return resolutionFailure(err)
			}

			var auditPayload *viewmodel.DiffAudit
			var sarifFindings []scan.Finding
			if current.Audit {
				scanRegistry := registry.BuildScanRegistry(logger, registryBuilderConfig(current))
				auditorFilter, err := resolveAuditorFilter(current.Auditors, scanRegistry)
				if err != nil {
					return invalidInputf("%v", err)
				}
				progress.Advance("Preparing audit output")
				baseGraph, err := baseConsolidated.Graphs.ConsolidatedGraph()
				if err != nil {
					return resolutionFailure(err)
				}
				headGraph, err := headConsolidated.Graphs.ConsolidatedGraph()
				if err != nil {
					return resolutionFailure(err)
				}
				baseEnrich := auditGraph(baseTarget.Context, logger, baseGraph, auditorFilter, streams.notificationWriter())
				headEnrich := auditGraph(headTarget.Context, logger, headGraph, auditorFilter, streams.notificationWriter())
				auditPayload = diffAuditSummary(baseEnrich.Findings, headEnrich.Findings)
				sarifFindings = append(append([]scan.Finding{}, headEnrich.Findings...), baseEnrich.Findings...)
				progress.CompleteStep("Found vulnerabilities", auditProgressChildren(sarifFindings, nil))
			}

			payload := viewmodel.BuildDiffResponse(projectIdentifier, compBase, compHead, baseConsolidated, headConsolidated, auditPayload, started)
			if outputFormat == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), sarifFindings, "bomly", cmd.Root().Version)
			}
			if current.Interactive {
				progress.Success("Resolved Graph")
				return runInteractiveModel(cmd.InOrStdin(), streams.interactiveWriter(), newDiffInteractiveModel(payload))
			}

			progress.Success("Resolved Graph")
			if outputFormat == output.FormatText {
				progress.SeparateReport()
			}
			return output.Write(streams.reportWriter(), outputFormat, payload, output.Renderers{
				Text: func(w io.Writer) error {
					return renderDiffText(w, payload)
				},
			})
		},
	}
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return invalidInputf("%v", err)
	})
	cmd.Flags().StringVar(&baseRef, "base", "", "Base git reference to compare (or SBOM file path when --sbom is set)")
	cmd.Flags().StringVar(&headRef, "head", "", "Head git reference to compare (or SBOM file path when --sbom is set)")
	return cmd
}

func resolveGitDiffGraphs(options *globalOptions, logger *zap.Logger, baseRef, headRef string, stderr io.Writer) (diffResolvedTarget, diffResolvedTarget, string, []scan.PipelineWarning, error) {
	repoRoot, repoCleanup, projectIdentifier, err := resolveDiffRepo(options, logger)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	if repoCleanup != nil {
		defer func() { _ = repoCleanup() }()
	}
	if err := gitutil.VerifyRef(repoRoot, baseRef); err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, invalidInputf("verify --base %q: %v", baseRef, err)
	}
	if err := gitutil.VerifyRef(repoRoot, headRef); err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, invalidInputf("verify --head %q: %v", headRef, err)
	}

	baseTarget, err := resolveDiffResultsForRef(options, logger, repoRoot, baseRef, stderr)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	headTarget, err := resolveDiffResultsForRef(options, logger, repoRoot, headRef, stderr)
	if err != nil {
		_ = baseTarget.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}

	return baseTarget, headTarget, projectIdentifier, collectPipelineWarnings(baseTarget.Warnings, headTarget.Warnings), nil
}

func resolveDiffRepo(options *globalOptions, logger *zap.Logger) (string, func() error, string, error) {
	if options.URL != "" {
		repoRoot, err := gitutil.CloneTemp(logger, options.URL, "")
		if err != nil {
			return "", nil, "", invalidInputf("clone --url %q: %v", options.URL, err)
		}
		return repoRoot, func() error { return os.RemoveAll(repoRoot) }, options.URL, nil
	}

	selectedPath, err := options.resolveProjectPath()
	if err != nil {
		return "", nil, "", err
	}
	repoRoot, err := gitutil.FindRepoRoot(selectedPath)
	if err != nil {
		return "", nil, "", invalidInputf("resolve local git repository: %v", err)
	}
	return repoRoot, nil, repoRoot, nil
}

func resolveDiffResultsForRef(options *globalOptions, logger *zap.Logger, repoRoot, ref string, stderr io.Writer) (diffResolvedTarget, error) {
	materializedPath, err := gitutil.MaterializeLocalRef(logger, repoRoot, ref)
	if err != nil {
		return diffResolvedTarget{}, resolutionFailure(err)
	}
	cleanup := func() error {
		return os.RemoveAll(materializedPath)
	}
	executionTarget := scan.ExecutionTarget{
		Kind:     scan.ExecutionTargetGitRepository,
		Location: materializedPath,
		Ref:      ref,
	}
	ctx, err := options.newCommandContextForExecutionTarget(logger, executionTarget, cleanup)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	resolution, err := resolveGraphs(ctx, logger, stderr)
	if err != nil {
		_ = ctx.close()
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: ctx, Results: resolution.Results, Warnings: resolution.DetectorWarnings}, nil
}

func resolveContainerDiffGraphs(options *globalOptions, logger *zap.Logger, baseRef, headRef string, stderr io.Writer) (diffResolvedTarget, diffResolvedTarget, string, []scan.PipelineWarning, error) {
	baseTarget, err := resolveContainerDiffTarget(options.Container, baseRef)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, invalidInputf("resolve --base %q: %v", baseRef, err)
	}
	headTarget, err := resolveContainerDiffTarget(options.Container, headRef)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, invalidInputf("resolve --head %q: %v", headRef, err)
	}

	baseResolved, err := resolveDiffResultsForExecutionTarget(options, logger, executionTargetForResolved(baseTarget), stderr)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	headResolved, err := resolveDiffResultsForExecutionTarget(options, logger, executionTargetForResolved(headTarget), stderr)
	if err != nil {
		_ = baseResolved.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}

	return baseResolved, headResolved, options.Container, collectPipelineWarnings(baseResolved.Warnings, headResolved.Warnings), nil
}

// executionTargetForResolved returns a filesystem target when the resolved location
// is a local path, otherwise a container image target.
func executionTargetForResolved(location string) scan.ExecutionTarget {
	if localPathExists(location) {
		return scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: location}
	}
	return scan.ExecutionTarget{Kind: scan.ExecutionTargetContainerImage, Location: location}
}

func resolveDiffResultsForExecutionTarget(options *globalOptions, logger *zap.Logger, executionTarget scan.ExecutionTarget, stderr io.Writer) (diffResolvedTarget, error) {
	ctx, err := options.newCommandContextForExecutionTarget(logger, executionTarget, nil)
	if err != nil {
		return diffResolvedTarget{}, err
	}

	resolution, err := resolveGraphs(ctx, logger, stderr)
	if err != nil {
		_ = ctx.close()
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: ctx, Results: resolution.Results, Warnings: resolution.DetectorWarnings}, nil
}

func collectPipelineWarnings(groups ...[]scan.PipelineWarning) []scan.PipelineWarning {
	var all []scan.PipelineWarning
	for _, g := range groups {
		all = append(all, g...)
	}
	return all
}

func resolveContainerDiffTarget(container, selector string) (string, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "", fmt.Errorf("image selector is empty")
	}
	if looksLikeContainerReference(selector) {
		return selector, nil
	}
	if localPathExists(selector) {
		absPath, absErr := system.Abs(selector)
		if absErr != nil {
			return "", absErr
		}
		return absPath, nil
	}
	container = strings.TrimSpace(container)
	if container == "" {
		return "", fmt.Errorf("--container is empty")
	}
	if strings.HasPrefix(selector, "sha256:") {
		return container + "@" + selector, nil
	}
	return container + ":" + selector, nil
}

func localPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func looksLikeContainerReference(value string) bool {
	switch {
	case strings.Contains(value, "@sha256:"):
		return true
	case strings.Contains(value, "/"):
		return true
	case strings.Count(value, ":") > 1:
		return true
	default:
		return false
	}
}

func diffManifestStatusOrder(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "removed":
		return 0
	case "added":
		return 1
	case "changed":
		return 2
	case "unchanged":
		return 3
	default:
		return 99
	}
}

func renderDiffText(w io.Writer, payload viewmodel.DiffResponse) error {
	if _, err := fmt.Fprintf(w, "Dependency diff %s -> %s\n", payload.Comparison.Base, payload.Comparison.Head); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		w,
		"Manifest changes: %d added, %d changed, %d unchanged, and %d removed\n",
		payload.Summary.AddedManifestCount,
		payload.Summary.ChangedManifestCount,
		payload.Summary.UnchangedManifestCount,
		payload.Summary.RemovedManifestCount,
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		w,
		"Package changes: %d added, %d updated, and %d removed\n",
		payload.Summary.AddedPackageCount,
		payload.Summary.ChangedPackageCount,
		payload.Summary.RemovedPackageCount,
	); err != nil {
		return err
	}
	if payload.Audit != nil {
		for _, line := range diffAuditTextSections(*payload.Audit) {
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
	}
	for _, line := range diffTextSections(payload.Results.Manifests) {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func diffAuditTextSections(audit viewmodel.DiffAudit) []string {
	lines := []string{
		"",
		"Audit Outcome",
		fmt.Sprintf("  Current findings: %s.", diffAuditFindingsSummary(audit.AuditSummary)),
		fmt.Sprintf(
			"  Change summary: %d introduced, %d persisted, and %d resolved findings.",
			len(audit.Introduced),
			len(audit.Persisted),
			len(audit.Resolved),
		),
	}

	if len(audit.Introduced) == 0 && len(audit.Persisted) == 0 && len(audit.Resolved) == 0 {
		return append(lines, "  No audit differences were identified between the base and head dependency sets.")
	}

	appendSection := func(title string, findings []viewmodel.AuditFinding, color string) {
		if len(findings) == 0 {
			return
		}
		lines = append(lines, "")
		lines = append(lines, title)
		for _, finding := range sortDiffAuditFindings(findings) {
			line := fmt.Sprintf("  - [%s] %s", strings.ToUpper(valueOrDash(finding.Severity)), valueOrDash(finding.ID))
			pkgLabel := diffPackageDisplayName(finding.Package)
			if pkgLabel != "" {
				line += " " + pkgLabel
			}
			if strings.TrimSpace(finding.Source) != "" {
				line += fmt.Sprintf(" (%s)", finding.Source)
			}
			if strings.TrimSpace(finding.Title) != "" && finding.Title != finding.ID {
				line += fmt.Sprintf(": %s", finding.Title)
			}
			if color != "" {
				line = ansiWrap(line, color)
			}
			lines = append(lines, line)
		}
	}

	appendSection("Introduced Findings", audit.Introduced, ansiRed)
	appendSection("Persisted Findings", audit.Persisted, "")
	appendSection("Resolved Findings", audit.Resolved, ansiGreen)

	return lines
}

func diffAuditFindingsSummary(summary *viewmodel.AuditSummary) string {
	if summary == nil || summary.Total == 0 {
		return "no active findings were reported"
	}
	return formatAuditSummary(summary, true)
}

func sortDiffAuditFindings(findings []viewmodel.AuditFinding) []viewmodel.AuditFinding {
	sorted := make([]viewmodel.AuditFinding, len(findings))
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
		pi := diffPackageDisplayName(sorted[i].Package)
		pj := diffPackageDisplayName(sorted[j].Package)
		if pi != pj {
			return pi < pj
		}
		return sorted[i].Title < sorted[j].Title
	})
	return sorted
}

func diffTextSections(manifests []viewmodel.DiffManifestResult) []string {
	lines := make([]string, 0, len(manifests)*8)
	appendSection := func(title string, values []string, indent string) {
		if len(values) == 0 {
			return
		}
		lines = append(lines, indent+title)
		for _, value := range values {
			lines = append(lines, indent+"- "+value)
		}
	}

	for _, manifest := range manifests {
		lines = append(lines, "")
		statusLine := fmt.Sprintf("%s manifest %s", strings.Title(manifest.Status), diffManifestDisplayLabel(manifest))
		switch manifest.Status {
		case "added":
			statusLine = ansiWrap(statusLine, ansiGreen)
		case "removed":
			statusLine = ansiWrap(statusLine, ansiRed)
		}
		lines = append(lines, statusLine)

		added := make([]string, 0, len(manifest.Added))
		for _, change := range manifest.Added {
			added = append(added, ansiWrap(diffPackageDisplayName(change.Package), ansiGreen))
		}
		changed := make([]string, 0, len(manifest.Changed))
		for _, change := range manifest.Changed {
			changed = append(changed, fmt.Sprintf("%s (%s -> %s)", diffPackageDisplayName(change.After), change.Before.Version, change.After.Version))
		}
		removed := make([]string, 0, len(manifest.Removed))
		for _, change := range manifest.Removed {
			removed = append(removed, ansiWrap(diffPackageDisplayName(change.Package), ansiRed))
		}

		appendSection("Added", added, "  ")
		appendSection("Changed", changed, "  ")
		appendSection("Removed", removed, "  ")
	}
	return lines
}

func diffPackageDisplayName(pkg output.PackageRef) string {
	switch {
	case pkg.Name != "" && pkg.Version != "":
		return pkg.Name + "@" + pkg.Version
	case pkg.Name != "":
		return pkg.Name
	case pkg.ID != "":
		return pkg.ID
	default:
		return ""
	}
}

func diffManifestDisplayLabel(manifest viewmodel.DiffManifestResult) string {
	label := manifest.Path
	if strings.TrimSpace(label) == "" {
		label = manifest.Kind
	}
	if strings.TrimSpace(manifest.PackageManager) != "" {
		return fmt.Sprintf("%s (%s)", label, manifest.PackageManager)
	}
	return label
}

// resolveSBOMDiffGraphs resolves dependency graph results for two SBOM files
// and returns them along with a human-readable comparison label.
func resolveSBOMDiffGraphs(
	options *globalOptions,
	logger *zap.Logger,
	basePath, headPath string,
	stderr io.Writer,
) (diffResolvedTarget, diffResolvedTarget, string, []scan.PipelineWarning, error) {
	baseResolved, err := resolveDiffResultsForSBOMFile(options, logger, basePath, stderr)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, fmt.Errorf("resolve base SBOM %q: %w", basePath, err)
	}
	headResolved, err := resolveDiffResultsForSBOMFile(options, logger, headPath, stderr)
	if err != nil {
		_ = baseResolved.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, fmt.Errorf("resolve head SBOM %q: %w", headPath, err)
	}
	label := fmt.Sprintf("%s vs %s", filepath.Base(basePath), filepath.Base(headPath))
	return baseResolved, headResolved, label, nil, nil
}

// resolveDiffResultsForSBOMFile builds one prepared runtime and graph resolution for an explicit SBOM file.
func resolveDiffResultsForSBOMFile(
	options *globalOptions,
	logger *zap.Logger,
	sbomPath string,
	stderr io.Writer,
) (diffResolvedTarget, error) {
	absPath, err := resolveExactFileTarget(sbomPath)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	executionTarget := scan.ExecutionTarget{
		Kind:     scan.ExecutionTargetFilesystem,
		Location: absPath,
	}
	ctx, err := options.newCommandContextForExecutionTarget(logger, executionTarget, nil)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	resolution, err := resolveGraphs(ctx, logger, stderr)
	if err != nil {
		_ = ctx.close()
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: ctx, Results: resolution.Results, Warnings: resolution.DetectorWarnings}, nil
}
