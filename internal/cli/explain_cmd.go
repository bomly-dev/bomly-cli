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
	model "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
)

func newExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <package>",
		Short: "Explain why a dependency exists",
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

			pipeline := engine.NewPipeline(context.Registry(), logger)
			explainResult, err := pipeline.RunExplain(cmd.Context(), engine.ExplainRequest{
				Query:    args[0],
				Pipeline: context.PipelineRequest(model.ScopeUnknown, streams.notificationWriter()),
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
			if context.Format == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), explainResult.Findings, "bomly", cmd.Root().Version)
			}
			if context.ResolvedConfig.Interactive {
				progress.Stop()
				return exit.InteractiveResult(tui.Run(cmd.InOrStdin(), streams.interactiveWriter(), tui.NewScanNavigator("Bomly Interactive Explain", payload.Project, explainResult.FocusedConsolidated, explainResult.FocusedGraph, explainResult.Findings)))
			}

			writer, closeWriter, err := context.Writer(streams.reportWriter())
			if err != nil {
				return err
			}
			defer func() { _ = closeWriter() }()
			progress.Success("Resolved Graph")
			if context.Format == output.FormatText {
				progress.SeparateReport()
			}

			err = output.Write(writer, context.Format, payload, output.Renderers{
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
			if err == nil && context.ResolvedConfig.Audit && len(explainResult.Findings) > 0 {
				return exit.PolicyViolationFindings(len(explainResult.Findings))
			}
			return err
		},
	}
	return cmd
}
