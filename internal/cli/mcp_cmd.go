package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	diffengine "github.com/bomly-dev/bomly-cli/internal/engine/diff"
	"github.com/bomly-dev/bomly-cli/internal/engine/explain"
	scanengine "github.com/bomly-dev/bomly-cli/internal/engine/scan"
	"github.com/bomly-dev/bomly-cli/internal/mcp"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/sdk"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newMcpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "MCP server for AI agent integration",
	}
	cmd.AddCommand(newMcpServeCmd())
	return cmd
}

func newMcpServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP stdio server",
		Long: "Start an MCP (Model Context Protocol) server over stdio. " +
			"Exposes bomly analysis capabilities as tools that AI agents (Claude, Cursor, etc.) can call.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			logger := commandLogger(cmd, "mcp")
			adapter := &mcpOptionsAdapter{
				options: options,
				logger:  logger,
				version: cmd.Root().Version,
			}
			s := mcp.NewServer(mcp.MCPContext{
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
	options *opts.Options
	logger  *zap.Logger
	version string
}

// cloneWithOverrides returns a copy of CommandContext with per-call values layered on top.
// The copy is safe to use concurrently — each call gets its own context and pipeline.
func (a *mcpOptionsAdapter) cloneWithOverrides(path, container, url, ref string, enrich, audit bool, failOn, ecosystems string) *opts.Options {
	clone := *a.options

	resolved := clone.GetConfig()
	applyStringOverride(&clone.ResolvedConfig.Path, path)
	applyStringOverride(&clone.ResolvedConfig.Container, container)
	applyStringOverride(&clone.ResolvedConfig.URL, url)
	applyStringOverride(&clone.ResolvedConfig.Ref, ref)
	applyStringOverride(&clone.ResolvedConfig.FailOn, failOn)
	applyStringOverride(&clone.ResolvedConfig.Ecosystems, ecosystems)
	if enrich {
		clone.ResolvedConfig.Enrich = true
	}
	if audit {
		clone.ResolvedConfig.Audit = true
	}
	clone.ResolvedConfig.Interactive = false

	applyStringOverride(&resolved.Path, path)
	applyStringOverride(&resolved.Container, container)
	applyStringOverride(&resolved.URL, url)
	applyStringOverride(&resolved.Ref, ref)
	applyStringOverride(&resolved.FailOn, failOn)
	applyStringOverride(&resolved.Ecosystems, ecosystems)
	if enrich {
		resolved.Enrich = true
	}
	if audit {
		resolved.Audit = true
	}
	resolved.Interactive = false
	clone.SetConfig(resolved)

	return &clone
}

func applyStringOverride(target *string, value string) {
	if value != "" {
		*target = value
	}
}

func (a *mcpOptionsAdapter) RunScan(ctx context.Context, req mcp.ScanRequest) (output.ScanResponse, error) {
	started := time.Now()
	o := a.cloneWithOverrides(req.Path, req.Container, req.URL, req.Ref, req.Enrich, req.Audit, req.FailOn, req.Ecosystems)
	cmdCtx, err := o.Prepare(ctx, a.logger)
	if err != nil {
		return output.ScanResponse{}, err
	}

	pipeline := engine.NewPipeline(cmdCtx.Registry(), a.logger)
	pipeReq := cmdCtx.PipelineRequest(sdk.ScopeUnknown, io.Discard)
	pipeResult, runErr := scanengine.Run(ctx, pipeline, pipeReq)
	if runErr != nil && len(pipeResult.ResolveResults) == 0 {
		return output.ScanResponse{}, runErr
	}

	var findings []sdk.Finding
	if cmdCtx.ResolvedConfig.Audit {
		findings = pipeResult.Findings
	}
	return output.BuildScanResponse(cmdCtx.ProjectDescriptor(), pipeResult.Consolidated, findings, started), nil
}

func (a *mcpOptionsAdapter) RunExplain(ctx context.Context, req mcp.ExplainRequest) (output.ExplainResponse, error) {
	started := time.Now()
	o := a.cloneWithOverrides(req.Path, "", "", "", req.Enrich, req.Audit, "", "")
	cmdCtx, err := o.Prepare(ctx, a.logger)
	if err != nil {
		return output.ExplainResponse{}, err
	}

	pipeline := engine.NewPipeline(cmdCtx.Registry(), a.logger)
	explainResult, err := pipeline.RunExplain(ctx, engine.ExplainRequest{
		Query:    req.Package,
		Pipeline: cmdCtx.PipelineRequest(sdk.ScopeUnknown, io.Discard),
	})
	if err != nil {
		return output.ExplainResponse{}, err
	}

	targets := make([]output.ExplainTargetResponse, 0, len(explainResult.Targets))
	for _, target := range explainResult.Targets {
		targets = append(targets, output.ExplainTargetResponse{
			Project:      cmdCtx.ProjectDescriptorForSubproject(target.Manifest.Subproject),
			Detector:     target.Manifest.DetectorName,
			Dependency:   explainPackageRef(target.Dependency),
			Paths:        explainPathsWithStableIDs(target.Paths),
			Findings:     output.FindingsFromScan(target.Findings),
			AuditSummary: output.SummaryFromFindings(target.Findings),
		})
	}
	return output.BuildExplainResponse(cmdCtx.ProjectDescriptor(), req.Package, targets, started), nil
}

func (a *mcpOptionsAdapter) RunDiff(ctx context.Context, req mcp.DiffRequest) (output.DiffResponse, error) {
	started := time.Now()
	o := a.cloneWithOverrides(req.Path, req.Container, "", "", req.Enrich, req.Audit, "", "")
	logger := a.logger

	baseTarget, headTarget, projectIdentifier, _, err := resolveGitDiffGraphs(ctx, o, logger, req.Base, req.Head, io.Discard)
	if err != nil {
		return output.DiffResponse{}, err
	}
	defer func() { _ = baseTarget.close() }()
	defer func() { _ = headTarget.close() }()

	diffResult, err := diffengine.Run(ctx, diffengine.Request{
		Base: diffengine.Target{
			Pipeline: engine.NewPipeline(baseTarget.Context.Registry(), logger),
			Request:  baseTarget.Context.PipelineRequest(sdk.ScopeUnknown, io.Discard),
		},
		Head: diffengine.Target{
			Pipeline: engine.NewPipeline(headTarget.Context.Registry(), logger),
			Request:  headTarget.Context.PipelineRequest(sdk.ScopeUnknown, io.Discard),
		},
	})
	if err != nil {
		return output.DiffResponse{}, err
	}

	return output.BuildDiffResponse(projectIdentifier, req.Base, req.Head, diffResult.Base.Consolidated, diffResult.Head.Consolidated, diffAuditOutput(diffResult.Audit), started), nil
}

func (a *mcpOptionsAdapter) ListPlugins(_ context.Context) ([]plugin.PluginInfo, error) {
	current := a.options.GetConfig()
	builtins := builtInPluginInfos(current, a.version)
	return plugin.ListPluginInfos("", builtins)
}

func (a *mcpOptionsAdapter) VulnFixContext(ctx context.Context, req mcp.VulnFixRequest) (mcp.VulnFixResult, error) {
	// Force enrich=true — vulnerability data is required for fix context.
	o := a.cloneWithOverrides(req.Path, "", "", "", true, false, "", "")
	cmdCtx, err := o.Prepare(ctx, a.logger)
	if err != nil {
		return mcp.VulnFixResult{}, err
	}

	pipeline := engine.NewPipeline(cmdCtx.Registry(), a.logger)
	pipeReq := cmdCtx.PipelineRequest(sdk.ScopeUnknown, io.Discard)
	pipeResult, runErr := scanengine.Run(ctx, pipeline, pipeReq)
	if runErr != nil && len(pipeResult.ResolveResults) == 0 {
		return mcp.VulnFixResult{}, runErr
	}

	consolidatedGraph := pipeResult.Graph
	if consolidatedGraph == nil {
		return mcp.VulnFixResult{}, fmt.Errorf("no dependency graph resolved")
	}

	dependency, paths, findErr := explain.FindWhy(consolidatedGraph, req.Package)
	if findErr != nil {
		return mcp.VulnFixResult{}, findErr
	}

	targetPkg, ok := consolidatedGraph.Package(dependency.ID)
	if !ok {
		return mcp.VulnFixResult{}, fmt.Errorf("package %q not found in graph", req.Package)
	}

	matchedVulns := collectVulns(targetPkg.Vulnerabilities, req.VulnID)
	if len(matchedVulns) == 0 {
		if req.VulnID != "" {
			return mcp.VulnFixResult{}, fmt.Errorf("vulnerability %q not found for package %q; run with enrich enabled to populate vulnerability data", req.VulnID, req.Package)
		}
		return mcp.VulnFixResult{}, fmt.Errorf("no vulnerabilities found for package %q; run with enrich enabled to populate vulnerability data", req.Package)
	}

	minSafeVersion := maxFixedIn(matchedVulns)
	vulnIDs := make([]string, len(matchedVulns))
	for i, v := range matchedVulns {
		vulnIDs[i] = v.ID
	}

	manifests := output.ScanManifestsFromConsolidated(pipeResult.Consolidated)
	affectedManifests := mcp.BuildManifestFixTargets(dependency, paths, minSafeVersion, manifests)
	recommendation := mcp.BuildRecommendationText(dependency, vulnIDs, minSafeVersion, affectedManifests)
	vulnRefs := output.VulnerabilityRefsFromPackageVulnerabilities(matchedVulns)

	return mcp.VulnFixResult{
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
func collectVulns(all []sdk.PackageVulnerability, vulnID string) []sdk.PackageVulnerability {
	if vulnID == "" {
		return all
	}
	for i, v := range all {
		if v.ID == vulnID {
			return []sdk.PackageVulnerability{all[i]}
		}
		for _, alias := range v.Aliases {
			if alias == vulnID {
				return []sdk.PackageVulnerability{all[i]}
			}
		}
	}
	return nil
}

// maxFixedIn returns the highest FixedIn version across the given vulnerabilities.
// Uses semver comparison when parseable; falls back to the last non-empty string.
func maxFixedIn(vulns []sdk.PackageVulnerability) string {
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
