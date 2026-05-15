package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	scanengine "github.com/bomly-dev/bomly-cli/internal/engine/scan"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/internal/tui"
	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var outputs []string
	var scopeValue string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan dependencies and render a graph or SBOM",
		Example: "  bomly scan --enrich --audit\n" +
			"  bomly scan -o spdx-json=bomly.spdx.json\n" +
			"  bomly scan --url https://github.com/bomly-dev/bomly-cli --ref main --format json\n" +
			"  bomly scan --container alpine:3.20",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			started := time.Now()
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			current := options.GetConfig()
			logger := commandLogger(cmd, "scan")
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			progress := newCommandProgress(streams, "Resolving dependencies")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if progress != nil {
					progress.Fail("Scan aborted")
				}
				restoreStdout()
			}()
			commandCtx, err := options.Prepare(cmd.Context(), logger)
			if err != nil {
				return err
			}
			defer func() { _ = commandCtx.Close() }()

			graphOutputFormat := commandCtx.Format
			if graphOutputFormat == output.FormatSARIF && !commandCtx.ResolvedConfig.Audit {
				return exit.InvalidInputError("--format sarif requires --audit")
			}
			selectedScope, err := sdk.ParseScope(scopeValue)
			if err != nil {
				return exit.InvalidInputError("%v", err)
			}

			var outputSpecs []render.SBOMOutputSpec
			if len(outputs) > 0 {
				outputSpecs, err = render.ParseSBOMOutputSpecs(outputs)
				if err != nil {
					return exit.InvalidInputError("%v", err)
				}
			}

			pipeline := engine.NewPipeline(commandCtx.Registry(), logger)
			progress.StartStage("Indexed subprojects", 1)
			progress.CompleteStage("Indexed subprojects", 1)
			pipeReq := commandCtx.PipelineRequest(selectedScope, streams.notificationWriter())
			pipeReq.Progress = progress
			pipeResult, err := scanengine.Run(cmd.Context(), pipeline, pipeReq)
			if err != nil {
				return exit.ResolutionFailureError(err)
			}
			resolved := pipeResult.ResolveResults
			subprojectChildren := subprojectProgressChildren(resolved)
			subprojectChildren = append(subprojectChildren, warningProgressChildren(pipeResult.DetectorWarnings)...)
			progress.CompleteStep("Indexed subprojects", subprojectChildren)
			progress.CompleteStep("Detected Dependencies", detectorProgressChildren(resolved))
			if len(pipeResult.MatcherRuns) > 0 || len(pipeResult.MatchWarnings) > 0 {
				progress.CompleteStep("Enriched packages", matchProgressChildren(pipeResult.Graph, pipeResult.MatcherRuns, pipeResult.MatchWarnings))
			}

			consolidated := pipeResult.Consolidated
			selectedGraph := pipeResult.Graph

			if len(outputSpecs) > 0 {
				progress.Advance("Writing SBOM output")
				stdout := streams.reportWriter()
				sbomBuildOpts := sbom.BuildOptions{ToolNames: sbomToolNames(resolved)}
				for _, spec := range outputSpecs {
					rawDocument, err := sbom.MarshalDepGraphJSON(selectedGraph, spec.Target, sbomBuildOpts, sbom.EncodeOptions{Pretty: true})
					if err != nil {
						return fmt.Errorf("marshal %s sbom: %w", spec.Label, err)
					}
					if err := render.WriteSBOMDocument(stdout, spec, rawDocument); err != nil {
						return err
					}
				}
				if !commandCtx.ResolvedConfig.Interactive {
					progress.Success("Wrote SBOM output")
					return nil
				}
			}

			var findings []sdk.Finding
			if commandCtx.ResolvedConfig.Audit {
				findings = pipeResult.Findings
				progress.CompleteStep("Evaluated policy", auditProgressChildren(pipeResult.AuditorRuns, pipeResult.AuditorFindings, pipeResult.AuditWarnings))
			}
			payload := output.BuildScanResponse(commandCtx.ProjectDescriptor(), consolidated, findings, started).
				WithAnalyzerRuns(pipeResult.AnalyzerRuns, pipeResult.AnalyzerStats)

			if graphOutputFormat == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), findings, "bomly", cmd.Root().Version)
			}

			if commandCtx.ResolvedConfig.Interactive {
				progress.Stop()
				return exit.InteractiveResult(tui.Run(cmd.InOrStdin(), streams.interactiveWriter(), tui.NewScan(payload.Project, consolidated, selectedGraph, findings).WithEnrichEnabled(commandCtx.ResolvedConfig.Enrich)))
			}

			writer, closeWriter, err := commandCtx.Writer(streams.reportWriter())
			if err != nil {
				return err
			}
			defer func() { _ = closeWriter() }()
			progress.Success("Resolved Graph")
			if commandCtx.Format == output.FormatText {
				progress.SeparateReport()
			}

			err = output.Write(writer, commandCtx.Format, payload, output.Renderers{
				Text: func(w io.Writer) error {
					if len(resolved) == 1 {
						if _, err := fmt.Fprintf(w, "Dependency report for %s\n\n", render.ScanGraphDisplayName(selectedGraph, payload.Project.Name)); err != nil {
							return err
						}
					} else {
						if _, err := fmt.Fprintf(w, "Dependency report for %d subprojects\n\n", len(resolved)); err != nil {
							return err
						}
					}
					_, err := io.WriteString(w, render.Scan(payload.Manifests, selectedGraph, findings, commandCtx.ResolvedConfig.Enrich, commandCtx.ResolvedConfig.Audit, commandCtx.ResolvedConfig.Reachability))
					return err
				},
			})
			if err == nil && commandCtx.ResolvedConfig.Audit && len(findings) > 0 {
				return exit.PolicyViolationFindings(len(findings))
			}
			return err
		},
	}
	cmd.Flags().StringArrayVarP(&outputs, "sbom-output", "o", nil, "SBOM output target as <format> or <format>=<path>; repeat for multiple outputs")
	cmd.Flags().StringVar(&scopeValue, "scope", "", "Filter dependencies by scope: runtime or development")
	return cmd
}

func sbomToolNames(results []sdk.DetectionResult) []string {
	tools := make([]string, 0, len(results))
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		if result.DetectorName == "" {
			continue
		}
		name := "bomly-detector:" + result.DetectorName
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		tools = append(tools, name)
	}
	return tools
}
