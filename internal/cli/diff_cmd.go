package cli

import (
	"io"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	"github.com/bomly-dev/bomly-cli/internal/scan/consolidation"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
)

type diffResolvedTarget struct {
	Context  commandContext
	Results  []model.DetectionResult
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
			allResults := append(append([]model.DetectionResult{}, baseResults...), headResults...)
			subprojectChildren := subprojectProgressChildren(allResults)
			subprojectChildren = append(subprojectChildren, warningProgressChildren(resolutionWarnings)...)
			progress.CompleteStep("Indexed subprojects", subprojectChildren)
			progress.CompleteStep("Detected Dependencies", detectorProgressChildren(allResults))
			if current.Enrich {
				progress.Advance("Enriching diff targets")
				baseResults = enrichResolvedGraphs(baseTarget.Context, logger, baseResults, streams.notificationWriter())
				headResults = enrichResolvedGraphs(headTarget.Context, logger, headResults, streams.notificationWriter())
				progress.CompleteStep("Enriched packages", matchProgressChildren(nil, []string{"matchers"}, nil))
			}

			baseConsolidated, err := consolidation.ConsolidateGraphs(baseResults)
			if err != nil {
				return resolutionFailure(err)
			}
			headConsolidated, err := consolidation.ConsolidateGraphs(headResults)
			if err != nil {
				return resolutionFailure(err)
			}

			var auditPayload *output.DiffAudit
			var sarifFindings []model.Finding
			if current.Audit {
				scanRegistry := scan.NewRegistry(registryBuilderConfig(current), *logger)
				scanRegistry.Build()
				auditorFilter, err := resolveAuditorFilter(current.Auditors, scanRegistry)
				if err != nil {
					return invalidInputf("%v", err)
				}
				progress.Advance("Evaluating policy")
				baseGraph, err := baseConsolidated.Graphs.ConsolidatedGraph()
				if err != nil {
					return resolutionFailure(err)
				}
				headGraph, err := headConsolidated.Graphs.ConsolidatedGraph()
				if err != nil {
					return resolutionFailure(err)
				}
				baseAudit := auditGraph(baseTarget.Context, logger, baseGraph, auditorFilter, streams.notificationWriter())
				headAudit := auditGraph(headTarget.Context, logger, headGraph, auditorFilter, streams.notificationWriter())
				auditPayload = diffAuditSummary(baseAudit.Findings, headAudit.Findings)
				sarifFindings = append(append([]model.Finding{}, headAudit.Findings...), baseAudit.Findings...)
				auditWarnings := auditDataAvailabilityWarnings(baseGraph, headGraph)
				progress.CompleteStep("Evaluated policy", auditProgressChildren([]string{severityPolicyAuditorName}, map[string]int{severityPolicyAuditorName: len(sarifFindings)}, auditWarnings))
			}

			payload := output.BuildDiffResponse(projectIdentifier, compBase, compHead, baseConsolidated, headConsolidated, auditPayload, started)
			if outputFormat == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), sarifFindings, "bomly", cmd.Root().Version)
			}
			if current.Interactive {
				progress.Stop()
				return runInteractiveModel(cmd.InOrStdin(), streams.interactiveWriter(), newDiffInteractiveModel(payload))
			}

			progress.Success("Resolved Graph")
			if outputFormat == output.FormatText {
				progress.SeparateReport()
			}
			err = output.Write(streams.reportWriter(), outputFormat, payload, output.Renderers{
				Text: func(w io.Writer) error {
					return renderDiffText(w, payload)
				},
			})
			if err == nil && current.Audit && auditPayload != nil && auditPayload.AuditSummary != nil && auditPayload.AuditSummary.Total > 0 {
				return policyViolationFindings(auditPayload.AuditSummary.Total)
			}
			return err
		},
	}
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return invalidInputf("%v", err)
	})
	cmd.Flags().StringVar(&baseRef, "base", "", "Base git reference to compare (or SBOM file path when --sbom is set)")
	cmd.Flags().StringVar(&headRef, "head", "", "Head git reference to compare (or SBOM file path when --sbom is set)")
	return cmd
}
