package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/internal/explain"
	bomcp "github.com/bomly-dev/bomly-cli/internal/mcp"
	"github.com/bomly-dev/bomly-cli/internal/output"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	model "github.com/bomly-dev/bomly-cli/sdk"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newMcpCmd(options *globalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "MCP server for AI agent integration",
	}
	cmd.AddCommand(newMcpServeCmd(options))
	return cmd
}

func newMcpServeCmd(options *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP stdio server",
		Long: "Start an MCP (Model Context Protocol) server over stdio. " +
			"Exposes bomly analysis capabilities as tools that AI agents (Claude, Cursor, etc.) can call.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := commandLogger(cmd, options, "mcp")
			adapter := &mcpOptionsAdapter{
				options: options,
				logger:  logger,
				version: cmd.Root().Version,
			}
			s := bomcp.NewServer(bomcp.MCPContext{
				Adapter: adapter,
				Version: cmd.Root().Version,
			})
			return mcpserver.ServeStdio(s)
		},
	}
}

// mcpOptionsAdapter implements bomcp.OptionsAdapter.
// It lives in package cli so it can call unexported pipeline helpers.
type mcpOptionsAdapter struct {
	options *globalOptions
	logger  *zap.Logger
	version string
}

// cloneWithOverrides returns a copy of globalOptions with per-call values layered on top.
// The copy is safe to use concurrently — each call gets its own context and pipeline.
func (a *mcpOptionsAdapter) cloneWithOverrides(path, container, url, ref string, enrich, audit bool, failOn, ecosystems string) *globalOptions {
	clone := *a.options

	// Deep-copy resolved config so per-call overrides don't mutate the server-level state.
	if clone.resolved != nil {
		resolved := *clone.resolved
		clone.resolved = &resolved
	}

	applyStringOverride(&clone.Path, path)
	applyStringOverride(&clone.Container, container)
	applyStringOverride(&clone.URL, url)
	applyStringOverride(&clone.Ref, ref)
	applyStringOverride(&clone.FailOn, failOn)
	applyStringOverride(&clone.Ecosystems, ecosystems)
	if enrich {
		clone.Enrich = true
	}
	if audit {
		clone.Audit = true
	}
	clone.Interactive = false

	if clone.resolved != nil {
		applyStringOverride(&clone.resolved.Path, path)
		applyStringOverride(&clone.resolved.Container, container)
		applyStringOverride(&clone.resolved.URL, url)
		applyStringOverride(&clone.resolved.Ref, ref)
		applyStringOverride(&clone.resolved.FailOn, failOn)
		applyStringOverride(&clone.resolved.Ecosystems, ecosystems)
		if enrich {
			clone.resolved.Enrich = true
		}
		if audit {
			clone.resolved.Audit = true
		}
		clone.resolved.Interactive = false
	}

	return &clone
}

func applyStringOverride(target *string, value string) {
	if value != "" {
		*target = value
	}
}

func (a *mcpOptionsAdapter) RunScan(ctx context.Context, req bomcp.ScanRequest) (output.ScanResponse, error) {
	started := time.Now()
	o := a.cloneWithOverrides(req.Path, req.Container, req.URL, req.Ref, req.Enrich, req.Audit, req.FailOn, req.Ecosystems)
	cmdCtx, err := o.newCommandContext(a.logger)
	if err != nil {
		return output.ScanResponse{}, err
	}
	defer func() { _ = cmdCtx.close() }()

	pipeline := newPipeline(cmdCtx, a.logger)
	pipeReq := pipelineRequest(cmdCtx, model.ScopeUnknown, io.Discard)
	pipeResult, runErr := pipeline.Run(ctx, pipeReq)
	if runErr != nil && len(pipeResult.ResolveResults) == 0 {
		return output.ScanResponse{}, runErr
	}

	var findings []model.Finding
	if cmdCtx.config.Audit {
		findings = deduplicateFindings(pipeResult.Findings)
	}
	return output.BuildScanResponse(cmdCtx.projectDescriptor(), pipeResult.Consolidated, findings, started), nil
}

func (a *mcpOptionsAdapter) RunExplain(ctx context.Context, req bomcp.ExplainRequest) (output.ExplainResponse, error) {
	started := time.Now()
	o := a.cloneWithOverrides(req.Path, "", "", "", req.Enrich, req.Audit, "", "")
	cmdCtx, err := o.newCommandContext(a.logger)
	if err != nil {
		return output.ExplainResponse{}, err
	}
	defer func() { _ = cmdCtx.close() }()

	resolution, err := resolveGraphs(cmdCtx, a.logger, io.Discard)
	if err != nil {
		return output.ExplainResponse{}, err
	}

	targets := make([]output.ExplainTargetResponse, 0, len(resolution.Results))
	for _, result := range resolution.Results {
		depsGraph, graphErr := result.ConsolidatedGraph()
		if graphErr != nil {
			return output.ExplainResponse{}, graphErr
		}
		if cmdCtx.config.Enrich {
			depsGraph = enrichGraph(cmdCtx, a.logger, depsGraph, result.SubprojectInfo, io.Discard)
		}
		dependency, paths, findErr := explain.FindWhy(depsGraph, req.Package)
		if findErr != nil {
			if errors.Is(findErr, explain.ErrDependencyNotFound) {
				continue
			}
			return output.ExplainResponse{}, findErr
		}
		var findings []model.Finding
		if cmdCtx.config.Audit {
			targetPkg, ok := depsGraph.Package(dependency.ID)
			if ok {
				findings = auditComponent(cmdCtx, a.logger, depsGraph, targetPkg, io.Discard).Findings
			}
		}
		targets = append(targets, output.ExplainTargetResponse{
			Project:      cmdCtx.projectDescriptorForSubproject(result.SubprojectInfo),
			Detector:     result.DetectorName,
			Dependency:   dependency,
			Paths:        paths,
			Findings:     output.FindingsFromScan(findings),
			AuditSummary: output.SummaryFromFindings(findings),
		})
	}
	if len(targets) == 0 {
		return output.ExplainResponse{}, fmt.Errorf("%w: %s", explain.ErrDependencyNotFound, req.Package)
	}
	return output.BuildExplainResponse(cmdCtx.projectDescriptor(), req.Package, targets, started), nil
}

func (a *mcpOptionsAdapter) RunDiff(ctx context.Context, req bomcp.DiffRequest) (output.DiffResponse, error) {
	started := time.Now()
	o := a.cloneWithOverrides(req.Path, req.Container, "", "", req.Enrich, req.Audit, "", "")
	logger := a.logger

	baseTarget, headTarget, projectIdentifier, _, err := resolveGitDiffGraphs(o, logger, req.Base, req.Head, io.Discard)
	if err != nil {
		return output.DiffResponse{}, err
	}
	defer func() { _ = baseTarget.close() }()
	defer func() { _ = headTarget.close() }()

	baseResults := baseTarget.Results
	headResults := headTarget.Results
	if req.Enrich {
		baseResults = enrichResolvedGraphs(baseTarget.Context, logger, baseResults, io.Discard)
		headResults = enrichResolvedGraphs(headTarget.Context, logger, headResults, io.Discard)
	}

	baseConsolidated, err := scan.ConsolidateGraphs(baseResults)
	if err != nil {
		return output.DiffResponse{}, err
	}
	headConsolidated, err := scan.ConsolidateGraphs(headResults)
	if err != nil {
		return output.DiffResponse{}, err
	}

	var auditPayload *output.DiffAudit
	if req.Audit {
		current := o.current()
		scanRegistry := scan.NewRegistry(registryBuilderConfig(current), *logger)
		scanRegistry.Build()
		auditorFilter, filterErr := resolveAuditorFilter(current.Auditors, scanRegistry)
		if filterErr != nil {
			return output.DiffResponse{}, filterErr
		}
		baseGraph, _ := baseConsolidated.Graphs.ConsolidatedGraph()
		headGraph, _ := headConsolidated.Graphs.ConsolidatedGraph()
		baseAudit := auditGraph(baseTarget.Context, logger, baseGraph, auditorFilter, io.Discard)
		headAudit := auditGraph(headTarget.Context, logger, headGraph, auditorFilter, io.Discard)
		auditPayload = diffAuditSummary(baseAudit.Findings, headAudit.Findings)
	}

	return output.BuildDiffResponse(projectIdentifier, req.Base, req.Head, baseConsolidated, headConsolidated, auditPayload, started), nil
}

func (a *mcpOptionsAdapter) ListPlugins(_ context.Context) ([]managedplugin.PluginInfo, error) {
	current := a.options.current()
	builtins := builtInPluginInfos(current, a.version)
	return managedplugin.ListPluginInfos("", builtins)
}

func (a *mcpOptionsAdapter) VulnFixContext(ctx context.Context, req bomcp.VulnFixRequest) (bomcp.VulnFixResult, error) {
	// Force enrich=true — vulnerability data is required for fix context.
	o := a.cloneWithOverrides(req.Path, "", "", "", true, false, "", "")
	cmdCtx, err := o.newCommandContext(a.logger)
	if err != nil {
		return bomcp.VulnFixResult{}, err
	}
	defer func() { _ = cmdCtx.close() }()

	pipeline := newPipeline(cmdCtx, a.logger)
	pipeReq := pipelineRequest(cmdCtx, model.ScopeUnknown, io.Discard)
	pipeResult, runErr := pipeline.Run(ctx, pipeReq)
	if runErr != nil && len(pipeResult.ResolveResults) == 0 {
		return bomcp.VulnFixResult{}, runErr
	}

	consolidatedGraph := pipeResult.Graph
	if consolidatedGraph == nil {
		return bomcp.VulnFixResult{}, fmt.Errorf("no dependency graph resolved")
	}

	dependency, paths, findErr := explain.FindWhy(consolidatedGraph, req.Package)
	if findErr != nil {
		return bomcp.VulnFixResult{}, findErr
	}

	targetPkg, ok := consolidatedGraph.Package(dependency.ID)
	if !ok {
		return bomcp.VulnFixResult{}, fmt.Errorf("package %q not found in graph", req.Package)
	}

	matchedVulns := collectVulns(targetPkg.Vulnerabilities, req.VulnID)
	if len(matchedVulns) == 0 {
		if req.VulnID != "" {
			return bomcp.VulnFixResult{}, fmt.Errorf("vulnerability %q not found for package %q; run with enrich enabled to populate vulnerability data", req.VulnID, req.Package)
		}
		return bomcp.VulnFixResult{}, fmt.Errorf("no vulnerabilities found for package %q; run with enrich enabled to populate vulnerability data", req.Package)
	}

	minSafeVersion := maxFixedIn(matchedVulns)
	vulnIDs := make([]string, len(matchedVulns))
	for i, v := range matchedVulns {
		vulnIDs[i] = v.ID
	}

	manifests := output.ScanManifestsFromConsolidated(pipeResult.Consolidated)
	affectedManifests := bomcp.BuildManifestFixTargets(dependency, paths, minSafeVersion, manifests)
	recommendation := bomcp.BuildRecommendationText(dependency, vulnIDs, minSafeVersion, affectedManifests)
	vulnRefs := output.VulnerabilityRefsFromPackageVulnerabilities(matchedVulns)

	return bomcp.VulnFixResult{
		Package:           dependency,
		Vulnerabilities:   vulnRefs,
		MinSafeVersion:    minSafeVersion,
		AffectedManifests: affectedManifests,
		Paths:             paths,
		Recommendation:    recommendation,
	}, nil
}

// collectVulns returns all vulnerabilities from the slice matching vulnID (by ID or alias).
// When vulnID is empty all vulnerabilities are returned.
func collectVulns(all []model.PackageVulnerability, vulnID string) []model.PackageVulnerability {
	if vulnID == "" {
		return all
	}
	for i, v := range all {
		if v.ID == vulnID {
			return []model.PackageVulnerability{all[i]}
		}
		for _, alias := range v.Aliases {
			if alias == vulnID {
				return []model.PackageVulnerability{all[i]}
			}
		}
	}
	return nil
}

// maxFixedIn returns the highest FixedIn version across the given vulnerabilities.
// Uses semver comparison when parseable; falls back to the last non-empty string.
func maxFixedIn(vulns []model.PackageVulnerability) string {
	var maxV *semver.Version
	var maxStr string
	for _, v := range vulns {
		if v.FixedIn == "" {
			continue
		}
		parsed, err := semver.NewVersion(v.FixedIn)
		if err != nil {
			if maxStr == "" {
				maxStr = v.FixedIn
			}
			continue
		}
		if maxV == nil || parsed.GreaterThan(maxV) {
			maxV = parsed
			maxStr = v.FixedIn
		}
	}
	return maxStr
}
