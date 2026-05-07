package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/cli/resolve"
	"github.com/bomly-dev/bomly-cli/internal/explain"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	"github.com/bomly-dev/bomly-cli/internal/scan/consolidation"
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
			resolution, err := resolve.ResolveGraphs(context, logger, streams.notificationWriter())
			if err != nil {
				return err
			}
			resolved := resolution.Results
			subprojectChildren := subprojectProgressChildren(resolved)
			subprojectChildren = append(subprojectChildren, warningProgressChildren(resolution.DetectorWarnings)...)
			progress.CompleteStep("Indexed subprojects", subprojectChildren)
			progress.CompleteStep("Detected Dependencies", detectorProgressChildren(resolved))
			progress.Advance("Finding dependency paths")
			auditWarnings := make([]scan.PipelineWarning, 0)

			targets := make([]output.ExplainTargetResponse, 0, len(resolved))
			focusedResults := make([]model.DetectionResult, 0, len(resolved))
			allFindings := make([]model.Finding, 0)
			anyVulnerabilityData := false
			for _, result := range resolved {
				depsGraph, graphErr := result.ConsolidatedGraph()
				if graphErr != nil {
					return exit.ResolutionFailureError(graphErr)
				}
				if context.ResolvedConfig.Enrich {
					depsGraph = resolve.EnrichGraph(context, logger, depsGraph, result.SubprojectInfo, streams.notificationWriter())
				}
				if scan.GraphHasVulnerabilityData(depsGraph) {
					anyVulnerabilityData = true
				}
				dependency, paths, findErr := explain.FindWhy(depsGraph, args[0])
				if findErr != nil {
					if errors.Is(findErr, explain.ErrDependencyNotFound) {
						continue
					}
					return exit.ResolutionFailureError(findErr)
				}
				findings := []model.Finding(nil)
				if context.ResolvedConfig.Audit {
					targetPkg, ok := depsGraph.Package(dependency.ID)
					if ok {
						findings = resolve.AuditComponent(context, logger, depsGraph, targetPkg, streams.notificationWriter()).Findings
						allFindings = append(allFindings, findings...)
					}
				}
				targets = append(targets, output.ExplainTargetResponse{
					Project:      context.ProjectDescriptorForSubproject(result.SubprojectInfo),
					Detector:     result.DetectorName,
					Dependency:   dependency,
					Paths:        paths,
					Findings:     output.FindingsFromScan(findings),
					AuditSummary: output.SummaryFromFindings(findings),
				})
				focusedGraph, focusErr := render.ExplainGraphFromPaths(depsGraph, paths)
				if focusErr != nil {
					return exit.ResolutionFailureError(focusErr)
				}
				focusedResults = append(focusedResults, model.DetectionResult{
					SubprojectInfo: result.SubprojectInfo,
					DetectorName:   result.DetectorName,
					Origin:         result.Origin,
					Technique:      result.Technique,
					Graphs:         scan.SingleGraphContainer(focusedGraph, render.ExplainManifestMetadata(result)),
				})
			}
			if len(targets) == 0 {
				return exit.ResolutionFailureError(fmt.Errorf("%w: %s", explain.ErrDependencyNotFound, args[0]))
			}
			if context.ResolvedConfig.Audit && !anyVulnerabilityData {
				auditWarnings = append(auditWarnings, resolve.AuditDataAvailabilityWarnings(nil)...)
			}
			if context.ResolvedConfig.Audit {
				progress.CompleteStep("Evaluated policy", auditProgressChildren([]string{opts.SeverityPolicyAuditorName}, map[string]int{opts.SeverityPolicyAuditorName: len(allFindings)}, auditWarnings))
			}

			payload := output.BuildExplainResponse(context.ProjectDescriptor(), args[0], targets, started)
			if context.Format == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), allFindings, "bomly", cmd.Root().Version)
			}
			if context.ResolvedConfig.Interactive {
				consolidated, err := consolidation.ConsolidateGraphs(focusedResults)
				if err != nil {
					return exit.ResolutionFailureError(err)
				}
				graphValue, err := consolidated.Graphs.ConsolidatedGraph()
				if err != nil {
					return exit.ResolutionFailureError(err)
				}
				progress.Stop()
				return exit.InteractiveResult(tui.Run(cmd.InOrStdin(), streams.interactiveWriter(), tui.NewScanNavigator("Bomly Interactive Explain", payload.Project, consolidated, graphValue, allFindings)))
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
			if err == nil && context.ResolvedConfig.Audit && len(allFindings) > 0 {
				return exit.PolicyViolationFindings(len(allFindings))
			}
			return err
		},
	}
	return cmd
}
