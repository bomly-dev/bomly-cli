package cli

import (
	"io"
	"sort"
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
			"  bomly diff --sbom --base ./before.cdx.json --head ./after.cdx.json --json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			logger := commandLogger(cmd, "diff")
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			prog := newCommandProgress(streams, "")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if prog != nil {
					prog.Fail("Diff aborted")
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
			if err := validatePrimaryReportFormat(outputFormat); err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if outputFormat == output.FormatSARIF && !current.Audit {
				return exit.InvalidInputError("--format sarif requires --audit")
			}
			outputSpecs, err := parseOutputSpecs(current.Outputs)
			if err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if err := validateReportOutputs(outputSpecs); err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if hasOutputFormat(outputSpecs, output.FormatSARIF) && !current.Audit {
				return exit.InvalidInputError("-o sarif requires --audit")
			}
			if current.Interactive && len(outputSpecs) > 0 {
				return exit.InvalidInputError("--output cannot be combined with --interactive")
			}

			var baseTarget diffResolvedTarget
			var headTarget diffResolvedTarget
			projectIdentifier := ""
			compBase := baseRef
			compHead := headRef
			var resolutionWarnings []engine.PipelineWarning

			switch {
			case current.SBOM:
				baseTarget, headTarget, projectIdentifier, resolutionWarnings, err = resolveSBOMDiffGraphs(cmd.Context(), options, prog, logger, baseRef, headRef)
			case current.Container != "":
				baseTarget, headTarget, projectIdentifier, resolutionWarnings, err = resolveContainerDiffGraphs(cmd.Context(), options, prog, logger, baseRef, headRef)
			default:
				baseTarget, headTarget, projectIdentifier, resolutionWarnings, err = resolveGitDiffGraphs(cmd.Context(), options, prog, logger, baseRef, headRef)
			}
			if err != nil {
				return err
			}
			defer func() { _ = baseTarget.close() }()
			defer func() { _ = headTarget.close() }()

			// Wire the engine pipeline progress reporter for both sides so the
			// user sees Detecting/Enriching/Auditing stages live for each ref.
			baseReq := baseTarget.Context.PipelineRequest(sdk.ScopeUnknown, streams.notificationWriter())
			baseReq.Progress = prog
			headReq := headTarget.Context.PipelineRequest(sdk.ScopeUnknown, streams.notificationWriter())
			headReq.Progress = prog
			diffResult, err := diffengine.Run(cmd.Context(), diffengine.Request{
				Base: diffengine.Target{
					Pipeline: engine.NewPipeline(baseTarget.Context.Registry(), logger),
					Request:  baseReq,
				},
				Head: diffengine.Target{
					Pipeline: engine.NewPipeline(headTarget.Context.Registry(), logger),
					Request:  headReq,
				},
			})
			if err != nil {
				return exit.ResolutionFailureError(err)
			}

			allResults := append(append([]sdk.DetectionResult{}, diffResult.Base.ResolveResults...), diffResult.Head.ResolveResults...)
			resolutionWarnings = append(resolutionWarnings, diffResult.Base.DetectorWarnings...)
			resolutionWarnings = append(resolutionWarnings, diffResult.Head.DetectorWarnings...)
			detectionChildren := detectorProgressChildren(allResults)
			detectionChildren = append(detectionChildren, warningProgressChildren(resolutionWarnings)...)
			prog.CompleteStep("Detected Dependencies", detectionChildren)
			if current.Enrich {
				stats := combineMatcherStats(diffResult.Base.MatcherStats, diffResult.Head.MatcherStats)
				warnings := append(append([]engine.PipelineWarning{}, diffResult.Base.MatchWarnings...), diffResult.Head.MatchWarnings...)
				prog.CompleteStep("Enriched packages", matchProgressChildren(stats, warnings))
			}

			auditPayload := diffAuditOutput(diffResult.Audit, diffResult.Base.Registry, diffResult.Head.Registry)
			if current.Audit {
				runs, findings := combineAuditProgress(diffResult.Base, diffResult.Head)
				warnings := append(append([]engine.PipelineWarning{}, diffResult.Base.AuditWarnings...), diffResult.Head.AuditWarnings...)
				children := append(auditProgressChildren(runs, findings, warnings), diffPolicyOutcomeProgressChild(diffResult.Audit))
				prog.CompleteStep("Evaluated policy", children)
			}

			reportOptions := reportOptionsFromPipelineResults(current.Analyze, diffResult.Base, diffResult.Head)
			reportOptions.BaseRegistry = diffResult.Base.Registry
			reportOptions.HeadRegistry = diffResult.Head.Registry
			payload := output.BuildDiffResponse(projectIdentifier, compBase, compHead, diffResult.Base.Consolidated, diffResult.Head.Consolidated, auditPayload, started, reportOptions)
			markdownRenderer := func(w io.Writer) error {
				return render.DiffMarkdown(w, payload)
			}
			textRenderer := func(w io.Writer) error {
				return render.Diff(w, payload)
			}
			reportRenderers := output.Renderers{
				Markdown: markdownRenderer,
				Text:     textRenderer,
			}
			sarifRenderer := func(w io.Writer) error {
				return output.WriteSARIF(w, diffResult.Findings, diffResult.Head.Registry, "bomly", cmd.Root().Version, output.SARIFOptions{IncludeReachability: current.Analyze, LocationGraphs: []*sdk.Graph{diffResult.Head.Graph, diffResult.Base.Graph}})
			}
			if len(outputSpecs) > 0 {
				prog.Advance("Writing additional output")
				for _, spec := range outputSpecs {
					if err := writeReportOutput(streams.reportWriter(), spec, payload, reportRenderers, sarifRenderer); err != nil {
						return err
					}
				}
			}
			if hasStdoutOutput(outputSpecs) {
				prog.Success("Wrote output")
				return diffPolicyExit(current.Audit, diffResult.Audit)
			}
			if outputFormat == output.FormatSARIF {
				prog.Success("Resolved Graph")
				return sarifRenderer(streams.reportWriter())
			}
			if current.Interactive {
				prog.Stop()
				return exit.InteractiveResult(tui.Run(cmd.InOrStdin(), streams.interactiveWriter(), tui.NewDiff(payload, diffResult.Base.Consolidated, diffResult.Head.Consolidated).WithRegistry(diffResult.Base.Registry, diffResult.Head.Registry).WithEnrichEnabled(current.Enrich)))
			}

			prog.Success("Resolved Graph")
			if outputFormat == output.FormatMarkdown || outputFormat == output.FormatText {
				prog.SeparateReport()
			}
			err = output.Write(streams.reportWriter(), outputFormat, payload, reportRenderers)
			if err == nil && current.Audit && diffResult.Audit != nil {
				if failing := output.FailingFindingCount(diffResult.Audit.Introduced); failing > 0 {
					return exit.PolicyViolationFindings(failing)
				}
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

func diffPolicyExit(auditEnabled bool, audit *diffengine.Audit) error {
	if auditEnabled && audit != nil {
		if failing := output.FailingFindingCount(audit.Introduced); failing > 0 {
			return exit.PolicyViolationFindings(failing)
		}
	}
	return nil
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

func combineMatcherStats(groups ...[]sdk.MatcherStats) []sdk.MatcherStats {
	byName := make(map[string]sdk.MatcherStats)
	order := make([]string, 0)
	for _, group := range groups {
		for _, stats := range group {
			if stats.Name == "" {
				continue
			}
			existing, ok := byName[stats.Name]
			if !ok {
				byName[stats.Name] = stats
				order = append(order, stats.Name)
				continue
			}
			if existing.DisplayName == "" {
				existing.DisplayName = stats.DisplayName
			}
			existing.MatchedPackages += stats.MatchedPackages
			existing.UnmatchedPackages += stats.UnmatchedPackages
			existing.Licenses += stats.Licenses
			existing.Vulnerabilities += stats.Vulnerabilities
			byName[stats.Name] = existing
		}
	}
	sort.Strings(order)
	out := make([]sdk.MatcherStats, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out
}
