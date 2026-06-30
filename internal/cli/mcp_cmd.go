package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/cli/render"
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
			s := mcp.NewServer(mcp.Context{
				Adapter: adapter,
				Version: cmd.Root().Version,
			})
			printMCPBanner(cmd.ErrOrStderr())
			return mcpserver.ServeStdio(s)
		},
	}
}

// printMCPBanner writes a brief startup notice to w (stderr) before the MCP
// stdio protocol begins. Output goes to stderr so it doesn't interfere with
// the JSON-RPC stream on stdout.
func printMCPBanner(w io.Writer) {
	type tool struct {
		name string
		desc string
	}
	tools := []tool{
		{"bomly_scan", "Scan a path, image, Git URL, or SBOM."},
		{"bomly_explain", "Show the dependency path for a package."},
		{"bomly_diff", "Compare dependency state across refs or SBOMs."},
		{"bomly_vuln_fix_context", "Get fix context for a vulnerability."},
		{"bomly_plugins", "List registered Bomly plugins."},
	}

	nameWidth := 0
	for _, t := range tools {
		if len(t.name) > nameWidth {
			nameWidth = len(t.name)
		}
	}

	fmt.Fprintf(w, "%s\n", render.Style("Starting Bomly MCP server (stdio) ...", render.Dim))
	fmt.Fprintf(w, "%s\n", render.Style("Registered tools:", render.Bold))
	for _, t := range tools {
		fmt.Fprintf(w, "  %s  %s\n",
			render.Style(fmt.Sprintf("%-*s", nameWidth, t.name), render.Cyan),
			render.Style(t.desc, render.Dim),
		)
	}
	fmt.Fprintf(w, "%s\n", render.Style("Awaiting client on stdio ...", render.Dim))
}

// mcpOptionsAdapter implements bomcp.OptionsAdapter.
// It lives in package cli so it can call unexported pipeline helpers.
type mcpOptionsAdapter struct {
	options *opts.Options
	logger  *zap.Logger
	version string
}

// mcpOverrides bundles every per-call value the MCP adapter layers on top
// of the resolved CommandContext. Adding a new MCP flag is a one-line
// addition here plus a one-line apply in cloneWithOverrides — no signature
// churn at every callsite.
type mcpOverrides struct {
	Path                  string
	Image                 string
	URL                   string
	Ref                   string
	Enrich                bool
	Audit                 bool
	Analyze               bool
	FailOn                string
	AllowVulnerabilityIDs string
	AllowLicenses         string
	DenyLicenses          string
	LicenseExemptPackages string
	DenyPackages          string
	DenyGroups            string
	ProtectedPackages     string
	TyposquatThreshold    string
	TyposquatMode         string
	WarnOnly              bool
	Ecosystems            string
}

// cloneWithOverrides returns a copy of CommandContext with per-call values layered on top.
// The copy is safe to use concurrently — each call gets its own context and pipeline.
func (a *mcpOptionsAdapter) cloneWithOverrides(o mcpOverrides) *opts.Options {
	clone := *a.options

	resolved := clone.GetConfig()
	applyStringOverride(&clone.ResolvedConfig.Path, o.Path)
	applyStringOverride(&clone.ResolvedConfig.Image, o.Image)
	applyStringOverride(&clone.ResolvedConfig.URL, o.URL)
	applyStringOverride(&clone.ResolvedConfig.Ref, o.Ref)
	applyFailOnOverride(&clone.ResolvedConfig.FailOn, o.FailOn)
	applyCSVOverride(&clone.ResolvedConfig.AllowVulnerabilityIDs, o.AllowVulnerabilityIDs)
	applyCSVOverride(&clone.ResolvedConfig.AllowLicenses, o.AllowLicenses)
	applyCSVOverride(&clone.ResolvedConfig.DenyLicenses, o.DenyLicenses)
	applyCSVOverride(&clone.ResolvedConfig.LicenseExemptPackages, o.LicenseExemptPackages)
	applyCSVOverride(&clone.ResolvedConfig.DenyPackages, o.DenyPackages)
	applyCSVOverride(&clone.ResolvedConfig.DenyGroups, o.DenyGroups)
	applyCSVOverride(&clone.ResolvedConfig.ProtectedPackages, o.ProtectedPackages)
	applyStringOverride(&clone.ResolvedConfig.TyposquatThreshold, o.TyposquatThreshold)
	applyStringOverride(&clone.ResolvedConfig.TyposquatMode, o.TyposquatMode)
	applyStringOverride(&clone.ResolvedConfig.Ecosystems, o.Ecosystems)
	if o.Enrich {
		clone.ResolvedConfig.Enrich = true
	}
	if o.Audit {
		clone.ResolvedConfig.Audit = true
	}
	if o.Analyze {
		clone.ResolvedConfig.Analyze = true
	}
	if o.WarnOnly {
		clone.ResolvedConfig.WarnOnly = true
	}
	clone.ResolvedConfig.Interactive = false

	applyStringOverride(&resolved.Path, o.Path)
	applyStringOverride(&resolved.Image, o.Image)
	applyStringOverride(&resolved.URL, o.URL)
	applyStringOverride(&resolved.Ref, o.Ref)
	applyFailOnOverride(&resolved.FailOn, o.FailOn)
	applyCSVOverride(&resolved.AllowVulnerabilityIDs, o.AllowVulnerabilityIDs)
	applyCSVOverride(&resolved.AllowLicenses, o.AllowLicenses)
	applyCSVOverride(&resolved.DenyLicenses, o.DenyLicenses)
	applyCSVOverride(&resolved.LicenseExemptPackages, o.LicenseExemptPackages)
	applyCSVOverride(&resolved.DenyPackages, o.DenyPackages)
	applyCSVOverride(&resolved.DenyGroups, o.DenyGroups)
	applyCSVOverride(&resolved.ProtectedPackages, o.ProtectedPackages)
	applyStringOverride(&resolved.TyposquatThreshold, o.TyposquatThreshold)
	applyStringOverride(&resolved.TyposquatMode, o.TyposquatMode)
	applyStringOverride(&resolved.Ecosystems, o.Ecosystems)
	if o.Enrich {
		resolved.Enrich = true
	}
	if o.Audit {
		resolved.Audit = true
	}
	if o.Analyze {
		resolved.Analyze = true
	}
	if o.WarnOnly {
		resolved.WarnOnly = true
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

// applyFailOnOverride accepts the legacy single-string MCP fail-on value
// and replaces target with a single-element slice when set. The MCP
// adapter does not yet expose the multi-constraint form.
func applyFailOnOverride(target *[]string, value string) {
	if strings.TrimSpace(value) != "" {
		*target = []string{value}
	}
}

func applyCSVOverride(target *[]string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	*target = out
}

func (a *mcpOptionsAdapter) RunScan(ctx context.Context, req mcp.ScanRequest) (output.ScanResponse, error) {
	started := time.Now()
	o := a.cloneWithOverrides(mcpOverrides{
		Path:       req.Path,
		Image:      req.Image,
		URL:        req.URL,
		Ref:        req.Ref,
		Enrich:     req.Enrich,
		Audit:      req.Audit,
		Analyze:    req.Analyze,
		FailOn:     req.FailOn,
		Ecosystems: req.Ecosystems,
	})
	cmdCtx, err := o.Prepare(ctx, a.logger)
	if err != nil {
		return output.ScanResponse{}, err
	}
	scopeFilter, err := sdk.ParseScope(req.Scope)
	if err != nil {
		return output.ScanResponse{}, err
	}

	pipeline := engine.NewPipeline(cmdCtx.Registry(), a.logger)
	pipeReq := cmdCtx.PipelineRequest(scopeFilter, io.Discard)
	pipeResult, runErr := scanengine.Run(ctx, pipeline, pipeReq)
	if runErr != nil && len(pipeResult.ResolveResults) == 0 {
		return output.ScanResponse{}, runErr
	}

	var findings []sdk.Finding
	if cmdCtx.ResolvedConfig.Audit {
		findings = pipeResult.Findings
	}
	return output.BuildScanResponse(
		cmdCtx.ProjectDescriptor(),
		pipeResult.Consolidated,
		pipeResult.Registry,
		findings,
		started,
		reportOptionsFromPipelineResults(cmdCtx.ResolvedConfig.Analyze, pipeResult),
	), nil
}

func (a *mcpOptionsAdapter) RunExplain(ctx context.Context, req mcp.ExplainRequest) (output.ExplainResponse, error) {
	started := time.Now()
	o := a.cloneWithOverrides(mcpOverrides{
		Path:    req.Path,
		Enrich:  req.Enrich,
		Audit:   req.Audit,
		Analyze: req.Analyze,
	})
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
			Project:        cmdCtx.ProjectDescriptorForSubproject(target.Manifest.Subproject),
			Detector:       target.Manifest.DetectorName,
			PackageManager: target.Manifest.Subproject.PrimaryPackageManager(),
			Dependency:     explainPackageRef(target.Dependency, explainResult.Registry),
			Paths:          explainPathsWithStableIDs(target.Paths),
			Findings:       output.FindingsFromScan(target.Findings, explainResult.Registry),
			AuditSummary:   output.SummaryFromFindings(target.Findings),
		})
	}
	return output.BuildExplainResponse(
		cmdCtx.ProjectDescriptor(),
		req.Package,
		targets,
		started,
		reportOptionsFromPipelineResults(cmdCtx.ResolvedConfig.Analyze, explainResult.PipelineResult),
	), nil
}

func (a *mcpOptionsAdapter) RunDiff(ctx context.Context, req mcp.DiffRequest) (output.DiffResponse, error) {
	started := time.Now()
	o := a.cloneWithOverrides(mcpOverrides{
		Path:                  req.Path,
		Image:                 req.Image,
		Enrich:                req.Enrich,
		Audit:                 req.Audit,
		Analyze:               req.Analyze,
		FailOn:                req.FailOn,
		AllowVulnerabilityIDs: req.AllowVulnerabilityIDs,
		AllowLicenses:         req.AllowLicenses,
		DenyLicenses:          req.DenyLicenses,
		LicenseExemptPackages: req.LicenseExemptPackages,
		DenyPackages:          req.DenyPackages,
		DenyGroups:            req.DenyGroups,
		ProtectedPackages:     req.ProtectedPackages,
		TyposquatThreshold:    req.TyposquatThreshold,
		TyposquatMode:         req.TyposquatMode,
		WarnOnly:              req.WarnOnly,
	})
	logger := a.logger

	baseTarget, headTarget, projectIdentifier, _, _, err := resolveGitDiffGraphs(ctx, o, nil, logger, req.Base, req.Head)
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

	reportOptions := reportOptionsFromPipelineResults(o.GetConfig().Analyze, diffResult.Base, diffResult.Head)
	reportOptions.BaseRegistry = diffResult.Base.Registry
	reportOptions.HeadRegistry = diffResult.Head.Registry

	return output.BuildDiffResponse(
		projectIdentifier,
		req.Base,
		req.Head,
		diffResult.Base.Consolidated,
		diffResult.Head.Consolidated,
		diffAuditOutput(diffResult.Audit, diffResult.Base.Registry, diffResult.Head.Registry),
		started,
		reportOptions,
	), nil
}

func (a *mcpOptionsAdapter) ListPlugins(_ context.Context) (plugin.ListResponse, error) {
	current := a.options.GetConfig()
	builtins := builtInPluginInfos(current, a.version)
	infos, err := plugin.ListPluginInfos("", builtins)
	if err != nil {
		return plugin.ListResponse{}, err
	}
	return plugin.GroupPluginInfos(infos), nil
}

func (a *mcpOptionsAdapter) VulnFixContext(ctx context.Context, req mcp.VulnFixRequest) (mcp.VulnFixResult, error) {
	// Force enrich=true — vulnerability data is required for fix context.
	o := a.cloneWithOverrides(mcpOverrides{Path: req.Path, Enrich: true})
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

	if _, ok := consolidatedGraph.Node(dependency.ID); !ok {
		return mcp.VulnFixResult{}, fmt.Errorf("package %q not found in graph", req.Package)
	}

	var registryPkgVulns []sdk.Vulnerability
	if pipeResult.Registry != nil {
		if pkg, ok := pipeResult.Registry.Get(dependency.Purl); ok && pkg != nil {
			registryPkgVulns = pkg.Vulnerabilities
		}
	}
	matchedVulns := collectVulns(registryPkgVulns, req.VulnID)
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

	manifests := output.ScanManifestsFromConsolidated(pipeResult.Consolidated, pipeResult.Registry)
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
func collectVulns(all []sdk.Vulnerability, vulnID string) []sdk.Vulnerability {
	if vulnID == "" {
		return all
	}
	for i, v := range all {
		if v.ID == vulnID {
			return []sdk.Vulnerability{all[i]}
		}
		for _, alias := range v.Aliases {
			if alias == vulnID {
				return []sdk.Vulnerability{all[i]}
			}
		}
	}
	return nil
}

// maxFixedIn returns the highest FixedIn version across the given vulnerabilities.
// Uses semver comparison when parseable; falls back to the last non-empty string.
func maxFixedIn(vulns []sdk.Vulnerability) string {
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
