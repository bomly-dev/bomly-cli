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
			"  bomly explain github.com/spf13/cobra --path .",
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
			progress := newCommandProgress(streams, "Resolving dependencies")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if progress != nil {
					progress.Fail("Explain aborted")
				}
				restoreStdout()
			}()
			context, err := options.Prepare(cmd.Context(), logger)
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
			if err := validateMarkdownOnlyOutputs(outputSpecs); err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if context.ResolvedConfig.Interactive && len(outputSpecs) > 0 {
				return exit.InvalidInputError("--output cannot be combined with --interactive")
			}

			pipeline := engine.NewPipeline(context.Registry(), logger)
			explainResult, err := pipeline.RunExplain(cmd.Context(), engine.ExplainRequest{
				Query:    args[0],
				Pipeline: context.PipelineRequest(sdk.ScopeUnknown, streams.notificationWriter()),
			})
			if err != nil {
				return exit.ResolutionFailureError(err)
			}

			resolved := explainResult.ResolveResults
			subprojectChildren := subprojectProgressChildren(resolved)
			subprojectChildren = append(subprojectChildren, warningProgressChildren(explainResult.DetectorWarnings)...)
			progress.CompleteStep("Indexed subprojects", subprojectChildren)
			progress.CompleteStep("Detected Dependencies", detectorProgressChildren(resolved))
			progress.Advance("Finding dependency paths")
			if len(explainResult.MatcherRuns) > 0 || len(explainResult.MatchWarnings) > 0 {
				progress.CompleteStep("Enriched packages", matchProgressChildren(explainResult.Graph, explainResult.MatcherRuns, explainResult.MatchWarnings))
			}

			targets := make([]output.ExplainTargetResponse, 0, len(explainResult.Targets))
			for _, target := range explainResult.Targets {
				targets = append(targets, output.ExplainTargetResponse{
					Project:      context.ProjectDescriptorForSubproject(target.Manifest.Subproject),
					Detector:     target.Manifest.DetectorName,
					Dependency:   explainPackageRef(target.Dependency),
					Paths:        explainPathsWithStableIDs(target.Paths),
					Findings:     output.FindingsFromScan(target.Findings),
					AuditSummary: output.SummaryFromFindings(target.Findings),
				})
			}
			if context.ResolvedConfig.Audit {
				progress.CompleteStep("Evaluated policy", auditProgressChildren(explainResult.AuditorRuns, explainResult.AuditorFindings, explainResult.AuditWarnings))
			}

			payload := output.BuildExplainResponse(context.ProjectDescriptor(), args[0], targets, started)
			markdownRenderer := func(w io.Writer) error {
				return render.ExplainMarkdown(w, payload)
			}
			if context.ResolvedConfig.Interactive {
				progress.Stop()
				return exit.InteractiveResult(tui.Run(cmd.InOrStdin(), streams.interactiveWriter(), tui.NewExplain(payload.Project, args[0], explainResult.FocusedConsolidated, explainResult.FocusedGraph, explainResult.Findings).WithEnrichEnabled(context.ResolvedConfig.Enrich)))
			}
			if len(outputSpecs) > 0 {
				progress.Advance("Writing additional output")
				for _, spec := range outputSpecs {
					if err := writeRenderedOutput(streams.reportWriter(), spec, markdownRenderer); err != nil {
						return err
					}
				}
			}
			if hasStdoutOutput(outputSpecs) {
				progress.Success("Wrote output")
				return explainPolicyExit(context.ResolvedConfig.Audit, explainResult.Findings)
			}
			if context.Format == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), explainResult.Findings, "bomly", cmd.Root().Version)
			}

			writer, closeWriter, err := context.Writer(streams.reportWriter())
			if err != nil {
				return err
			}
			defer func() { _ = closeWriter() }()
			progress.Success("Resolved Graph")
			if context.Format == output.FormatText || context.Format == output.FormatMarkdown {
				progress.SeparateReport()
			}

			err = output.Write(writer, context.Format, payload, output.Renderers{
				Markdown: markdownRenderer,
				Text: func(w io.Writer) error {
					for i, target := range payload.Targets {
						if i > 0 {
							if _, err := fmt.Fprintln(w); err != nil {
								return err
							}
						}
						if err := render.Explain(w, target); err != nil {
							return err
						}
					}
					return nil
				},
			})
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
