package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
)

func newScanCmd(options *globalOptions) *cobra.Command {
	var outputs []string
	var scopeValue string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan dependencies and render a graph or SBOM",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			started := time.Now()
			current := options.current()
			logger := commandLogger(cmd, options, "scan")
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			progress := newCommandProgress(streams, "Resolving dependencies")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if progress != nil {
					progress.Fail("Scan aborted")
				}
				restoreStdout()
			}()
			ctx, err := options.newCommandContext(logger)
			if err != nil {
				return err
			}
			defer func() { _ = ctx.close() }()

			graphOutputFormat := ctx.format
			if graphOutputFormat == output.FormatSARIF && !ctx.config.Audit {
				return invalidInputf("--format sarif requires --audit")
			}
			selectedScope, err := model.ParseScope(scopeValue)
			if err != nil {
				return invalidInputf("%v", err)
			}

			var outputSpecs []sbomOutputSpec
			if len(outputs) > 0 {
				outputSpecs, err = parseSBOMOutputSpecs(outputs)
				if err != nil {
					return invalidInputf("%v", err)
				}
			}

			pipeline := newPipeline(ctx, logger)
			progress.StartStage("Indexed subprojects", 1)
			progress.CompleteStage("Indexed subprojects", 1)
			pipeReq := pipelineRequest(ctx, selectedScope, streams.notificationWriter())
			pipeReq.Progress = progress
			pipeResult, err := pipeline.Run(cmd.Context(), pipeReq)
			if err != nil {
				return resolutionFailure(err)
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
				for _, spec := range outputSpecs {
					rawDocument, err := sbom.MarshalDepGraphJSON(selectedGraph, spec.target, sbom.BuildOptions{}, sbom.EncodeOptions{Pretty: true})
					if err != nil {
						return fmt.Errorf("marshal %s sbom: %w", spec.label, err)
					}
					if err := writeSBOMDocument(stdout, spec, rawDocument); err != nil {
						return err
					}
				}
				if !ctx.config.Interactive {
					progress.Success("Wrote SBOM output")
					return nil
				}
			}

			var enrichResult auditEnrichResult
			if ctx.config.Audit {
				enrichResult.Findings = deduplicateFindings(pipeResult.Findings)
				progress.CompleteStep("Evaluated policy", auditProgressChildren(pipeResult.AuditorRuns, pipeResult.AuditorFindings, pipeResult.AuditWarnings))
			}
			payload := output.BuildScanResponse(ctx.projectDescriptor(), consolidated, enrichResult.Findings, started)

			if graphOutputFormat == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), enrichResult.Findings, "bomly", cmd.Root().Version)
			}

			if ctx.config.Interactive {
				progress.Stop()
				return runInteractiveModel(cmd.InOrStdin(), streams.interactiveWriter(), newScanInteractiveModel(payload.Project, consolidated, selectedGraph, enrichResult.Findings))
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
					if len(resolved) == 1 {
						if _, err := fmt.Fprintf(w, "Dependency report for %s\n\n", scanGraphDisplayName(selectedGraph, payload.Project.Name)); err != nil {
							return err
						}
					} else {
						if _, err := fmt.Fprintf(w, "Dependency report for %d subprojects\n\n", len(resolved)); err != nil {
							return err
						}
					}
					_, err := io.WriteString(w, renderScanReport(payload.Manifests, selectedGraph, enrichResult.Findings, ctx.config.Enrich, ctx.config.Audit))
					return err
				},
			})
			if err == nil && ctx.config.Audit && len(enrichResult.Findings) > 0 {
				return policyViolationFindings(len(enrichResult.Findings))
			}
			return err
		},
	}
	cmd.Flags().StringArrayVarP(&outputs, "sbom-output", "o", nil, "SBOM output target as <format> or <format>=<path>; repeat for multiple outputs")
	cmd.Flags().StringVar(&scopeValue, "scope", "", "Filter dependencies by scope: runtime or development")
	return cmd
}
