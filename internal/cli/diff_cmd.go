package cli

import (
	"io"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	diffengine "github.com/bomly-dev/bomly-cli/internal/engine/diff"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/tui"
	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
)

type diffResolvedTarget struct {
	Context  opts.Options
	Warnings []engine.PipelineWarning
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
		Long:  "Compare dependency states between two git refs, two SBOM files, or two container image tags/digests.",
		Example: "  bomly diff --url https://github.com/bomly-dev/bomly-cli --base main --head feature\n" +
			"  bomly diff --container alpine --base 3.19 --head 3.20 --enrich\n" +
			"  bomly diff --sbom --base ./before.cdx.json --head ./after.cdx.json --format json",
		Args: cobra.NoArgs,
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
			var resolutionWarnings []engine.PipelineWarning

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
			defer func() { _ = baseTarget.close() }()
			defer func() { _ = headTarget.close() }()

			diffResult, err := diffengine.Run(cmd.Context(), diffengine.Request{
				Base: diffengine.Target{
					Pipeline: engine.NewPipeline(baseTarget.Context.Registry(), logger),
					Request:  baseTarget.Context.PipelineRequest(sdk.ScopeUnknown, streams.notificationWriter()),
				},
				Head: diffengine.Target{
					Pipeline: engine.NewPipeline(headTarget.Context.Registry(), logger),
					Request:  headTarget.Context.PipelineRequest(sdk.ScopeUnknown, streams.notificationWriter()),
				},
			})
			if err != nil {
				return exit.ResolutionFailureError(err)
			}

			allResults := append(append([]sdk.DetectionResult{}, diffResult.Base.ResolveResults...), diffResult.Head.ResolveResults...)
			resolutionWarnings = append(resolutionWarnings, diffResult.Base.DetectorWarnings...)
			resolutionWarnings = append(resolutionWarnings, diffResult.Head.DetectorWarnings...)
			subprojectChildren := subprojectProgressChildren(allResults)
			subprojectChildren = append(subprojectChildren, warningProgressChildren(resolutionWarnings)...)
			progress.CompleteStep("Indexed subprojects", subprojectChildren)
			progress.CompleteStep("Detected Dependencies", detectorProgressChildren(allResults))
			if current.Enrich {
				runs := uniqueStrings(diffResult.Base.MatcherRuns, diffResult.Head.MatcherRuns)
				warnings := append(append([]engine.PipelineWarning{}, diffResult.Base.MatchWarnings...), diffResult.Head.MatchWarnings...)
				progress.CompleteStep("Enriched packages", matchProgressChildren(nil, runs, warnings))
			}

			auditPayload := diffAuditOutput(diffResult.Audit)
			if current.Audit {
				runs, findings := combineAuditProgress(diffResult.Base, diffResult.Head)
				warnings := append(append([]engine.PipelineWarning{}, diffResult.Base.AuditWarnings...), diffResult.Head.AuditWarnings...)
				progress.CompleteStep("Evaluated policy", auditProgressChildren(runs, findings, warnings))
			}

			payload := output.BuildDiffResponse(projectIdentifier, compBase, compHead, diffResult.Base.Consolidated, diffResult.Head.Consolidated, auditPayload, started)
			if outputFormat == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), diffResult.Findings, "bomly", cmd.Root().Version)
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

func uniqueStrings(groups ...[]string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, group := range groups {
		for _, value := range group {
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func combineAuditProgress(results ...engine.PipelineResult) ([]string, map[string]int) {
	var runs []string
	counts := make(map[string]int)
	for _, result := range results {
		runs = uniqueStrings(runs, result.AuditorRuns)
		for name, count := range result.AuditorFindings {
			counts[name] += count
		}
	}
	return runs, counts
}
