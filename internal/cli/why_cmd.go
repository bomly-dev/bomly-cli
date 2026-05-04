package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/explain"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	"github.com/bomly-dev/bomly-cli/internal/scan/consolidation"
	"github.com/bomly-dev/bomly-cli/internal/tui"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
)

func newExplainCmd(options *globalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <package>",
		Short: "Explain why a dependency exists",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return invalidInputf("explain expects exactly one package argument")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			started := time.Now()
			current := options.current()
			logger := commandLogger(cmd, options, "explain")
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			progress := newCommandProgress(streams, "Resolving dependencies")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if progress != nil {
					progress.Fail("Explain aborted")
				}
				restoreStdout()
			}()
			ctx, err := options.newCommandContext(logger)
			if err != nil {
				return err
			}
			defer func() { _ = ctx.close() }()
			if ctx.format == output.FormatSARIF && !ctx.config.Audit {
				return invalidInputf("--format sarif requires --audit")
			}
			resolution, err := resolveGraphs(ctx, logger, streams.notificationWriter())
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
					return resolutionFailure(graphErr)
				}
				if ctx.config.Enrich {
					depsGraph = enrichGraph(ctx, logger, depsGraph, result.SubprojectInfo, streams.notificationWriter())
				}
				if scan.GraphHasVulnerabilityData(depsGraph) {
					anyVulnerabilityData = true
				}
				dependency, paths, findErr := explain.FindWhy(depsGraph, args[0])
				if findErr != nil {
					if errors.Is(findErr, explain.ErrDependencyNotFound) {
						continue
					}
					return resolutionFailure(findErr)
				}
				findings := []model.Finding(nil)
				if ctx.config.Audit {
					targetPkg, ok := depsGraph.Package(dependency.ID)
					if ok {
						findings = auditComponent(ctx, logger, depsGraph, targetPkg, streams.notificationWriter()).Findings
						allFindings = append(allFindings, findings...)
					}
				}
				targets = append(targets, output.ExplainTargetResponse{
					Project:      ctx.projectDescriptorForSubproject(result.SubprojectInfo),
					Detector:     result.DetectorName,
					Dependency:   dependency,
					Paths:        paths,
					Findings:     output.FindingsFromScan(findings),
					AuditSummary: output.SummaryFromFindings(findings),
				})
				focusedGraph, focusErr := render.ExplainGraphFromPaths(depsGraph, paths)
				if focusErr != nil {
					return resolutionFailure(focusErr)
				}
				focusedResults = append(focusedResults, model.DetectionResult{
					SubprojectInfo: result.SubprojectInfo,
					DetectorName:   result.DetectorName,
					ComponentType:  result.ComponentType,
					Graphs:         scan.SingleGraphContainer(focusedGraph, render.ExplainManifestMetadata(result)),
				})
			}
			if len(targets) == 0 {
				return resolutionFailure(fmt.Errorf("%w: %s", explain.ErrDependencyNotFound, args[0]))
			}
			if ctx.config.Audit && !anyVulnerabilityData {
				auditWarnings = append(auditWarnings, auditDataAvailabilityWarnings(nil)...)
			}
			if ctx.config.Audit {
				progress.CompleteStep("Evaluated policy", auditProgressChildren([]string{severityPolicyAuditorName}, map[string]int{severityPolicyAuditorName: len(allFindings)}, auditWarnings))
			}

			payload := output.BuildExplainResponse(ctx.projectDescriptor(), args[0], targets, started)
			if ctx.format == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), allFindings, "bomly", cmd.Root().Version)
			}
			if ctx.config.Interactive {
				consolidated, err := consolidation.ConsolidateGraphs(focusedResults)
				if err != nil {
					return resolutionFailure(err)
				}
				graphValue, err := consolidated.Graphs.ConsolidatedGraph()
				if err != nil {
					return resolutionFailure(err)
				}
				progress.Stop()
				return interactiveResult(tui.Run(cmd.InOrStdin(), streams.interactiveWriter(), tui.NewScanNavigator("Bomly Interactive Explain", payload.Project, consolidated, graphValue, allFindings)))
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
			if err == nil && ctx.config.Audit && len(allFindings) > 0 {
				return policyViolationFindings(len(allFindings))
			}
			return err
		},
	}
	return cmd
}
