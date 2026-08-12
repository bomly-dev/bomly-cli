package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	scanengine "github.com/bomly-dev/bomly-cli/internal/engine/scan"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/internal/tui"
	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/system"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var scopeValue string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan dependencies and render a graph or SBOM",
		Example: "  bomly scan --enrich --audit\n" +
			"  bomly scan -o spdx=bomly.spdx.json\n" +
			"  bomly scan --url https://github.com/bomly-dev/bomly-cli --ref main --json\n" +
			"  bomly scan --image alpine:3.20",
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
			prog := newCommandProgress(streams, "")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if prog != nil {
					prog.Fail("Scan aborted")
				}
				restoreStdout()
			}()

			// Two-phase pre-pipeline setup with explicit progress steps:
			//   1. Resolve execution target (clone repo / read SBOM / resolve
			//      container) — shown only when there's actual work to do.
			//   2. Index subprojects (registry build, plugin load, plan) —
			//      always shown, always completes before the pipeline starts.
			commandCtx, err := prepareCommandContextWithProgress(cmd.Context(), options, prog, logger)
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

			outputSpecs, err := parseOutputSpecs(current.Outputs)
			if err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if hasOutputFormat(outputSpecs, output.FormatSARIF) && !commandCtx.ResolvedConfig.Audit {
				return exit.InvalidInputError("-o sarif requires --audit")
			}
			if current.Interactive && hasStdoutOutput(outputSpecs) {
				return exit.InvalidInputError("--interactive cannot be combined with stdout --output")
			}

			pipeline := engine.NewPipeline(commandCtx.Registry(), logger)
			pipeReq := commandCtx.PipelineRequest(selectedScope, streams.notificationWriter())
			pipeReq.Progress = prog
			pipeResult, err := scanengine.Run(cmd.Context(), pipeline, pipeReq)
			if err != nil {
				return exit.ResolutionFailureError(err)
			}
			resolved := pipeResult.ResolveResults
			detectionChildren := detectorProgressChildren(resolved)
			detectionChildren = append(detectionChildren, detectorWarningProgressChildren(pipeResult.DetectorWarnings)...)
			prog.CompleteStep("Detected Dependencies", detectionChildren)
			if len(pipeResult.MatcherStats) > 0 || len(pipeResult.MatchWarnings) > 0 {
				prog.CompleteStep("Enriched packages", matchProgressChildren(pipeResult.MatcherStats, pipeResult.MatchWarnings))
			}
			if commandCtx.ResolvedConfig.Analyze {
				prog.CompleteStep("Analyzed reachability", analyzerProgressChildren(pipeResult.AnalyzerRuns, pipeResult.AnalyzerStats, pipeResult.AnalyzeWarnings))
			}

			consolidated := pipeResult.Consolidated
			selectedGraph := pipeResult.Graph

			var findings []sdk.Finding
			if commandCtx.ResolvedConfig.Audit {
				findings = pipeResult.Findings
				prog.CompleteStep("Evaluated policy", auditProgressChildren(pipeResult.AuditorRuns, pipeResult.AuditorFindings, pipeResult.AuditWarnings))
			}
			reportOptions := reportOptionsFromPipelineResults(commandCtx.ResolvedConfig.Analyze, pipeResult)
			payload := output.BuildScanResponse(commandCtx.ProjectDescriptor(), consolidated, pipeResult.Registry, findings, started, reportOptions)
			markdownRenderer := func(w io.Writer) error {
				return render.ScanMarkdown(w, payload)
			}
			scanManifests := output.ScanManifestsFromConsolidated(consolidated, pipeResult.Registry)
			// Notices ride the report itself, not just the progress stream, so
			// -q and non-terminal CI runs still surface degraded resolution and
			// CI-readiness problems.
			notices := render.WarningNotices(payload.Warnings)
			textRenderer := func(w io.Writer) error {
				if _, err := io.WriteString(w, render.Scan(selectedGraph, pipeResult.Registry, findings, pipeResult.MatcherStats, commandCtx.ResolvedConfig.Enrich, commandCtx.ResolvedConfig.Audit, commandCtx.ResolvedConfig.Analyze, commandCtx.ResolvedConfig.FailOn, scanManifests, notices)); err != nil {
					return fmt.Errorf("write scan text output: %w", err)
				}
				return nil
			}
			reportRenderers := output.Renderers{
				Markdown: markdownRenderer,
				Text:     textRenderer,
			}
			sarifRenderer := func(w io.Writer) error {
				return output.WriteSARIF(w, findings, pipeResult.Registry, "bomly", cmd.Root().Version, output.SARIFOptions{IncludeReachability: commandCtx.ResolvedConfig.Analyze, LocationGraphs: []*sdk.Graph{pipeResult.Graph}})
			}

			sbomBuildOpts := scanSBOMBuildOptions(payload.Project, commandCtx.ResolvedConfig, cmd.Root().Version, resolved, pipeResult.Registry, selectedScope, len(pipeResult.DetectorWarnings) > 0)

			if len(outputSpecs) > 0 {
				prog.Advance("Writing additional output")
				stdout := streams.reportWriter()
				for _, spec := range outputSpecs {
					switch {
					case spec.IsSBOM():
						rawDocument, err := sbom.MarshalDepGraphJSON(selectedGraph, spec.Target, sbomBuildOpts, sbom.EncodeOptions{Pretty: true})
						if err != nil {
							return fmt.Errorf("marshal %s sbom: %w", spec.Label, err)
						}
						if err := render.WriteOutputDocument(stdout, spec, rawDocument); err != nil {
							return err
						}
					default:
						if err := writeReportOutput(stdout, spec, payload, reportRenderers, sarifRenderer); err != nil {
							return err
						}
					}
				}
			}
			if hasStdoutOutput(outputSpecs) || (allOutputsAreSBOM(outputSpecs) && strings.TrimSpace(current.Format) == "") {
				prog.Success("Wrote output")
				return scanPolicyExit(commandCtx.ResolvedConfig.Audit, findings)
			}

			if graphOutputFormat.IsSBOM() {
				target, ok := render.SBOMTarget(graphOutputFormat)
				if !ok {
					return exit.InvalidInputError("output format %q is not supported by scan", graphOutputFormat)
				}
				rawDocument, err := sbom.MarshalDepGraphJSON(selectedGraph, target, sbomBuildOpts, sbom.EncodeOptions{Pretty: true})
				if err != nil {
					return fmt.Errorf("marshal %s sbom: %w", graphOutputFormat, err)
				}
				prog.Success("Wrote output")
				if err := render.WriteOutputDocument(streams.reportWriter(), render.OutputSpec{Format: graphOutputFormat, Label: string(graphOutputFormat)}, rawDocument); err != nil {
					return err
				}
				return scanPolicyExit(commandCtx.ResolvedConfig.Audit, findings)
			}

			if graphOutputFormat == output.FormatSARIF {
				prog.Success("Resolved Graph")
				return sarifRenderer(streams.reportWriter())
			}

			if commandCtx.ResolvedConfig.Interactive {
				prog.Stop()
				return exit.InteractiveResult(tui.Run(cmd.InOrStdin(), streams.interactiveWriter(), tui.NewScan(payload.Project, consolidated, selectedGraph, findings).WithRegistry(pipeResult.Registry).WithEnrichEnabled(commandCtx.ResolvedConfig.Enrich).WithReachabilityEnabled(commandCtx.ResolvedConfig.Analyze)))
			}

			writer, closeWriter, err := commandCtx.Writer(streams.reportWriter())
			if err != nil {
				return err
			}
			defer func() { _ = closeWriter() }()

			prog.Success("Resolved Graph")
			if commandCtx.Format == output.FormatText || commandCtx.Format == output.FormatMarkdown {
				prog.SeparateReport()
			}

			err = output.Write(writer, commandCtx.Format, payload, reportRenderers)
			if err == nil && commandCtx.ResolvedConfig.Audit {
				if failing := output.FailingFindingCount(findings); failing > 0 {
					return exit.PolicyViolationFindings(failing)
				}
			}
			return err
		},
	}
	cmd.Flags().StringVar(&scopeValue, "scope", "", "Filter dependencies by scope: runtime or development")
	return cmd
}

func scanPolicyExit(auditEnabled bool, findings []sdk.Finding) error {
	if auditEnabled {
		if failing := output.FailingFindingCount(findings); failing > 0 {
			return exit.PolicyViolationFindings(failing)
		}
	}
	return nil
}

// scanSBOMBuildOptions assembles the SBOM projection options for a scan: the
// document is named after the scanned project, the primary component mirrors
// it, and optional provenance metadata comes from configuration.
func scanSBOMBuildOptions(project output.ProjectDescriptor, current config.Resolved, version string, resolved []sdk.DetectionResult, registry *sdk.PackageRegistry, selectedScope sdk.Scope, degraded bool) sbom.BuildOptions {
	opts := sbom.BuildOptions{
		ToolNames:   sbomToolNames(resolved),
		ToolVersion: strings.TrimSpace(version),
		Registry:    registry,
		Lifecycle:   sbomLifecyclePhase(project.TargetType),
		Aggregate:   sbomCompositionAggregate(selectedScope, degraded),
		Provenance: sbom.Provenance{
			Manufacturer:               strings.TrimSpace(current.SBOMManufacturer),
			SecurityContact:            strings.TrimSpace(current.SBOMSecurityContact),
			VulnerabilityDisclosureURL: strings.TrimSpace(current.SBOMVulnerabilityDisclosureURL),
			SupportEnd:                 strings.TrimSpace(current.SBOMSupportEnd),
		},
	}
	if name := strings.TrimSpace(project.Name); name != "" {
		projectVersion := strings.TrimSpace(project.TargetRef)
		if projectVersion == "" {
			projectVersion = gitDescribeVersion(project.Path)
		}
		opts.DocumentName = name
		opts.ProjectRoot = &sbom.ProjectRoot{Name: name, Version: projectVersion}
	}
	return opts
}

// sbomLifecyclePhase maps the execution target type onto a CycloneDX
// lifecycle phase: source trees are pre-build inventories, container images
// describe a built artifact. Other targets (for example re-exported SBOMs)
// carry no phase claim.
func sbomLifecyclePhase(targetType string) string {
	switch targetType {
	case "filesystem", "git repository":
		return "pre-build"
	case "container image":
		return "post-build"
	default:
		return ""
	}
}

// sbomCompositionAggregate declares dependency-graph completeness. A scope
// filter deliberately drops part of the graph, and degraded resolution means
// completeness is unknown; only an unfiltered, warning-free scan may claim
// "complete".
func sbomCompositionAggregate(selectedScope sdk.Scope, degraded bool) string {
	if degraded {
		return "unknown"
	}
	if selectedScope != sdk.ScopeUnknown && selectedScope != "" {
		return "incomplete"
	}
	return "complete"
}

// gitDescribeVersion derives a project version from Git history when the scan
// target is a checkout with no explicit ref (local path scans). Returns ""
// when Git or history is unavailable — the version is then simply omitted.
func gitDescribeVersion(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	gitPath, err := system.LookPath("git")
	if err != nil {
		return ""
	}
	cmd := system.Command(gitPath, "-C", path, "describe", "--tags", "--always", "--dirty")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
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
