package cli

import (
	"io"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/cli/resolve"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	"github.com/bomly-dev/bomly-cli/internal/scan/consolidation"
	"github.com/bomly-dev/bomly-cli/internal/tui"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
)

type diffResolvedTarget struct {
	Context  opts.Options
	Results  []model.DetectionResult
	Warnings []scan.PipelineWarning
}

func (t diffResolvedTarget) close() error {
	return t.Context.Close()
}

func newDiffCmd() *cobra.Command {
	var baseRef string
	var headRef string

	cmd := &cobra.Command{
		Use:   "diff --base <ref> --head <ref>",
		Short: "Compare dependency states",
		Long:  "Compare dependency states between two git refs or two container image tags/digests.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			logger := commandLogger(cmd, "diff")
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			progress := newCommandProgress(streams, "Resolving diff inputs")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if progress != nil {
					progress.Fail("Diff aborted")
				}
				restoreStdout()
			}()
			if current.Ref != "" {
				return exit.InvalidInputError("diff does not support --ref; use --base and --head")
			}

			// Validate SBOM diff mode vs git diff mode flag combinations.
			if current.SBOM {
				if baseRef == "" {
					return exit.InvalidInputError("--base is required when --sbom is set")
				}
				if headRef == "" {
					return exit.InvalidInputError("--head is required when --sbom is set")
				}
				if current.Container != "" {
					return exit.InvalidInputError("--sbom cannot be combined with --container")
				}
			} else {
				if baseRef == "" {
					return exit.InvalidInputError("--base is required (or use --sbom to treat refs as SBOM file paths)")
				}
				if headRef == "" {
					return exit.InvalidInputError("--head is required (or use --sbom to treat refs as SBOM file paths)")
				}
			}

			started := time.Now()
			outputFormat, err := options.OutputFormat()
			if err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if outputFormat == output.FormatSARIF && !current.Audit {
				return exit.InvalidInputError("--format sarif requires --audit")
			}

			var baseTarget diffResolvedTarget
			var headTarget diffResolvedTarget
			projectIdentifier := ""
			compBase := baseRef
			compHead := headRef
			var resolutionWarnings []scan.PipelineWarning

			switch {
			case current.SBOM:
				baseTarget, headTarget, projectIdentifier, resolutionWarnings, err = resolveSBOMDiffGraphs(cmd.Context(), options, logger, baseRef, headRef, streams.notificationWriter())
			case current.Container != "":
				baseTarget, headTarget, projectIdentifier, resolutionWarnings, err = resolveContainerDiffGraphs(cmd.Context(), options, logger, baseRef, headRef, streams.notificationWriter())
			default:
				baseTarget, headTarget, projectIdentifier, resolutionWarnings, err = resolveGitDiffGraphs(cmd.Context(), options, logger, baseRef, headRef, streams.notificationWriter())
			}
			if err != nil {
				return err
			}

			baseResults := baseTarget.Results
			headResults := headTarget.Results
			allResults := append(append([]model.DetectionResult{}, baseResults...), headResults...)
			subprojectChildren := subprojectProgressChildren(allResults)
			subprojectChildren = append(subprojectChildren, warningProgressChildren(resolutionWarnings)...)
			progress.CompleteStep("Indexed subprojects", subprojectChildren)
			progress.CompleteStep("Detected Dependencies", detectorProgressChildren(allResults))
			if current.Enrich {
				progress.Advance("Enriching diff targets")
				baseResults = resolve.EnrichResolvedGraphs(baseTarget.Context, logger, baseResults, streams.notificationWriter())
				headResults = resolve.EnrichResolvedGraphs(headTarget.Context, logger, headResults, streams.notificationWriter())
				progress.CompleteStep("Enriched packages", matchProgressChildren(nil, []string{"matchers"}, nil))
			}

			baseConsolidated, err := consolidation.ConsolidateGraphs(baseResults)
			if err != nil {
				return exit.ResolutionFailureError(err)
			}
			headConsolidated, err := consolidation.ConsolidateGraphs(headResults)
			if err != nil {
				return exit.ResolutionFailureError(err)
			}

			var auditPayload *output.DiffAudit
			var sarifFindings []model.Finding
			if current.Audit {
				scanRegistry := scan.NewRegistry(resolve.RegistryBuilderConfig(current), *logger)
				scanRegistry.Build()
				auditorFilter, err := opts.ResolveAuditorFilter(current.Auditors, scanRegistry)
				if err != nil {
					return exit.InvalidInputError("%v", err)
				}
				progress.Advance("Evaluating policy")
				baseGraph, err := baseConsolidated.Graphs.ConsolidatedGraph()
				if err != nil {
					return exit.ResolutionFailureError(err)
				}
				headGraph, err := headConsolidated.Graphs.ConsolidatedGraph()
				if err != nil {
					return exit.ResolutionFailureError(err)
				}
				baseAudit := resolve.AuditGraph(baseTarget.Context, logger, baseGraph, auditorFilter, streams.notificationWriter())
				headAudit := resolve.AuditGraph(headTarget.Context, logger, headGraph, auditorFilter, streams.notificationWriter())
				auditPayload = resolve.DiffAuditSummary(baseAudit.Findings, headAudit.Findings)
				sarifFindings = append(append([]model.Finding{}, headAudit.Findings...), baseAudit.Findings...)
				auditWarnings := resolve.AuditDataAvailabilityWarnings(baseGraph, headGraph)
				progress.CompleteStep("Evaluated policy", auditProgressChildren([]string{opts.SeverityPolicyAuditorName}, map[string]int{opts.SeverityPolicyAuditorName: len(sarifFindings)}, auditWarnings))
			}

			payload := output.BuildDiffResponse(projectIdentifier, compBase, compHead, baseConsolidated, headConsolidated, auditPayload, started)
			if outputFormat == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), sarifFindings, "bomly", cmd.Root().Version)
			}
			if current.Interactive {
				progress.Stop()
				return exit.InteractiveResult(tui.Run(cmd.InOrStdin(), streams.interactiveWriter(), tui.NewDiff(payload)))
			}

			progress.Success("Resolved Graph")
			if outputFormat == output.FormatText {
				progress.SeparateReport()
			}
			err = output.Write(streams.reportWriter(), outputFormat, payload, output.Renderers{
				Text: func(w io.Writer) error {
					return render.Diff(w, payload)
				},
			})
			if err == nil && current.Audit && auditPayload != nil && auditPayload.AuditSummary != nil && auditPayload.AuditSummary.Total > 0 {
				return exit.PolicyViolationFindings(auditPayload.AuditSummary.Total)
			}
			return err
		},
	}
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return exit.InvalidInputError("%v", err)
	})
	cmd.Flags().StringVar(&baseRef, "base", "", "Base git reference to compare (or SBOM file path when --sbom is set)")
	cmd.Flags().StringVar(&headRef, "head", "", "Head git reference to compare (or SBOM file path when --sbom is set)")
	return cmd
}
