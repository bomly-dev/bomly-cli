package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/tui"
	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
)

func newExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <package>",
		Short: "Explain why a dependency exists",
		Example: "  bomly explain pkg:npm/react\n" +
			"  bomly explain github.com/spf13/cobra --path . --json",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return exit.InvalidInputError("explain expects exactly one package argument")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			started := time.Now()
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			current := options.GetConfig()
			logger := commandLogger(cmd, "explain")
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			prog := newCommandProgress(streams, "")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if prog != nil {
					prog.Fail("Explain aborted")
				}
				restoreStdout()
			}()
			requestedFormat, err := options.OutputFormat()
			if err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if err := validatePrimaryReportFormat(requestedFormat); err != nil {
				return exit.InvalidInputError("%v", err)
			}

			// Two-phase pre-pipeline setup: resolve execution target (only
			// when non-local) and index subprojects. Each gets its own
			// progress line that completes before detection starts.
			context, err := prepareCommandContextWithProgress(cmd.Context(), options, prog, logger)
			if err != nil {
				return err
			}
			defer func() { _ = context.Close() }()
			if context.Format == output.FormatSARIF && !context.ResolvedConfig.Audit {
				return exit.InvalidInputError("--format sarif requires --audit")
			}
			outputSpecs, err := parseOutputSpecs(context.ResolvedConfig.Outputs)
			if err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if err := validateReportOutputs(outputSpecs); err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if hasOutputFormat(outputSpecs, output.FormatSARIF) && !context.ResolvedConfig.Audit {
				return exit.InvalidInputError("-o sarif requires --audit")
			}
			if context.ResolvedConfig.Interactive && len(outputSpecs) > 0 {
				return exit.InvalidInputError("--output cannot be combined with --interactive")
			}

			pipeline := engine.NewPipeline(context.Registry(), logger)
			pipeReq := context.PipelineRequest(sdk.ScopeUnknown, streams.notificationWriter())
			pipeReq.Progress = prog
			explainResult, err := pipeline.RunExplain(cmd.Context(), engine.ExplainRequest{
				Query:    args[0],
				Pipeline: pipeReq,
			})
			if err != nil {
				return exit.ResolutionFailureError(err)
			}

			resolved := explainResult.ResolveResults
			detectionChildren := detectorProgressChildren(resolved)
			detectionChildren = append(detectionChildren, warningProgressChildren(explainResult.DetectorWarnings)...)
			prog.CompleteStep("Detected Dependencies", detectionChildren)
			prog.Advance("Finding dependency paths")
			if len(explainResult.MatcherRuns) > 0 || len(explainResult.MatchWarnings) > 0 {
				prog.CompleteStep("Enriched packages", matchProgressChildren(explainResult.Registry, explainResult.MatcherRuns, explainResult.MatchWarnings))
			}

			targets := make([]output.ExplainTargetResponse, 0, len(explainResult.Targets))
			for _, target := range explainResult.Targets {
				targets = append(targets, output.ExplainTargetResponse{
					Project:      context.ProjectDescriptorForSubproject(target.Manifest.Subproject),
					Detector:     target.Manifest.DetectorName,
					Dependency:   explainPackageRef(target.Dependency),
					Paths:        explainPathsWithStableIDs(target.Paths),
					Findings:     output.FindingsFromScan(target.Findings, explainResult.Registry),
					AuditSummary: output.SummaryFromFindings(target.Findings),
				})
			}
			if context.ResolvedConfig.Audit {
				prog.CompleteStep("Evaluated policy", auditProgressChildren(explainResult.AuditorRuns, explainResult.AuditorFindings, explainResult.AuditWarnings))
			}

			reportOptions := reportOptionsFromPipelineResults(context.ResolvedConfig.Reachability, explainResult.PipelineResult)
			payload := output.BuildExplainResponse(context.ProjectDescriptor(), args[0], targets, started, reportOptions)
			markdownRenderer := func(w io.Writer) error {
				return render.ExplainMarkdown(w, payload)
			}
			textRenderer := func(w io.Writer) error {
				for i, target := range payload.Targets {
					if i > 0 {
						if _, err := fmt.Fprintln(w); err != nil {
							return err
						}
					}
					if err := render.Explain(w, target, payload.Metadata.ReachabilityEnabled); err != nil {
						return err
					}
				}
				return nil
			}
			reportRenderers := output.Renderers{
				Markdown: markdownRenderer,
				Text:     textRenderer,
			}
			sarifRenderer := func(w io.Writer) error {
				return output.WriteSARIF(w, explainResult.Findings, explainResult.Registry, "bomly", cmd.Root().Version, output.SARIFOptions{IncludeReachability: context.ResolvedConfig.Reachability})
			}
			if context.ResolvedConfig.Interactive {
				prog.Stop()
				return exit.InteractiveResult(tui.Run(cmd.InOrStdin(), streams.interactiveWriter(), tui.NewExplain(payload.Project, args[0], explainResult.FocusedConsolidated, explainResult.FocusedGraph, explainResult.Findings).WithRegistry(explainResult.Registry).WithEnrichEnabled(context.ResolvedConfig.Enrich)))
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
				return explainPolicyExit(context.ResolvedConfig.Audit, explainResult.Findings)
			}
			if context.Format == output.FormatSARIF {
				prog.Success("Resolved Graph")
				return sarifRenderer(streams.reportWriter())
			}

			writer, closeWriter, err := context.Writer(streams.reportWriter())
			if err != nil {
				return err
			}
			defer func() { _ = closeWriter() }()
			prog.Success("Resolved Graph")
			if context.Format == output.FormatText || context.Format == output.FormatMarkdown {
				prog.SeparateReport()
			}

			err = output.Write(writer, context.Format, payload, reportRenderers)
			if err == nil && context.ResolvedConfig.Audit {
				if failing := output.FailingFindingCount(explainResult.Findings); failing > 0 {
					return exit.PolicyViolationFindings(failing)
				}
			}
			return err
		},
	}
	return cmd
}

func explainPolicyExit(auditEnabled bool, findings []sdk.Finding) error {
	if auditEnabled {
		if failing := output.FailingFindingCount(findings); failing > 0 {
			return exit.PolicyViolationFindings(failing)
		}
	}
	return nil
}
