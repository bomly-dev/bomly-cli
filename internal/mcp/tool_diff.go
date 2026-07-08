package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerDiffTool(s *server.MCPServer, mcpCtx Context) {
	tool := mcplib.NewTool("bomly_diff",
		mcplib.WithDescription("Compare dependency state between two targets and answer: what does head fix vs base, what does it introduce, and what remains open after merge? By default base and head are Git refs; set image to diff container tags/digests, or sbom to diff two SBOM files. With enrich+audit the response carries a security delta (introduced / resolved / persisted findings, keyed by advisory id independent of version bumps) plus remediation groups for everything still open. Compact by design; use bomly_explain on the head checkout for full advisory detail of one package."),
		mcplib.WithString("base",
			mcplib.Required(),
			mcplib.Description("Base to compare: a Git ref (e.g. main, HEAD~1, a SHA), a container tag/digest when image is set, or an SBOM file path when sbom is true"),
		),
		mcplib.WithString("head",
			mcplib.Required(),
			mcplib.Description("Head to compare: a Git ref (e.g. HEAD, a branch, a SHA), a container tag/digest when image is set, or an SBOM file path when sbom is true"),
		),
		mcplib.WithString("path", mcplib.Description("Local repository path (defaults to cwd)")),
		mcplib.WithString("image", mcplib.Description("Container image reference to diff; base and head are treated as tags/digests (e.g. alpine)")),
		mcplib.WithString("container", mcplib.Description("Deprecated alias for image")),
		mcplib.WithBoolean("sbom", mcplib.Description("Treat base and head as SBOM file paths (SPDX or CycloneDX) instead of Git refs")),
		mcplib.WithBoolean("enrich", mcplib.Description("Enrich packages with vulnerability and license data")),
		mcplib.WithBoolean("audit", mcplib.Description("Include audit delta (introduced, resolved, and persisted findings) (requires enrich)")),
		mcplib.WithBoolean("analyze", mcplib.Description("Run code analysis on each side and include reachability annotations on the audit delta (requires enrich)")),
		mcplib.WithString("fail_on", mcplib.Description("Vulnerability threshold constraint, such as high, reachable, or exploitable")),
		mcplib.WithString("allow_vulnerability_ids", mcplib.Description("Comma-separated vulnerability IDs to ignore")),
		mcplib.WithString("allow_licenses", mcplib.Description("Comma-separated SPDX licenses to allow")),
		mcplib.WithString("deny_licenses", mcplib.Description("Comma-separated SPDX licenses to deny")),
		mcplib.WithString("license_exempt_packages", mcplib.Description("Comma-separated package URLs exempt from license checks")),
		mcplib.WithString("deny_packages", mcplib.Description("Comma-separated package URLs to deny")),
		mcplib.WithString("deny_groups", mcplib.Description("Comma-separated package URL namespaces to deny")),
		mcplib.WithString("protected_packages", mcplib.Description("Comma-separated package names to protect from typosquatting")),
		mcplib.WithString("typosquat_threshold", mcplib.Description("Typosquatting similarity threshold")),
		mcplib.WithString("typosquat_mode", mcplib.Description("Typosquatting mode: warn or fail")),
		mcplib.WithBoolean("warn_only", mcplib.Description("Downgrade failing findings to warnings")),
	)
	s.AddTool(tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		base, err := req.RequireString("base")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		head, err := req.RequireString("head")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		diffReq := DiffRequest{
			Base:                  base,
			Head:                  head,
			Path:                  req.GetString("path", ""),
			Image:                 firstNonEmpty(req.GetString("image", ""), req.GetString("container", "")),
			SBOM:                  req.GetBool("sbom", false),
			Enrich:                req.GetBool("enrich", false),
			Audit:                 req.GetBool("audit", false),
			Analyze:               req.GetBool("analyze", false),
			FailOn:                req.GetString("fail_on", ""),
			AllowVulnerabilityIDs: req.GetString("allow_vulnerability_ids", ""),
			AllowLicenses:         req.GetString("allow_licenses", ""),
			DenyLicenses:          req.GetString("deny_licenses", ""),
			LicenseExemptPackages: req.GetString("license_exempt_packages", ""),
			DenyPackages:          req.GetString("deny_packages", ""),
			DenyGroups:            req.GetString("deny_groups", ""),
			ProtectedPackages:     req.GetString("protected_packages", ""),
			TyposquatThreshold:    req.GetString("typosquat_threshold", ""),
			TyposquatMode:         req.GetString("typosquat_mode", ""),
			WarnOnly:              req.GetBool("warn_only", false),
		}
		result, err := mcpCtx.Adapter.RunDiff(ctx, diffReq)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return jsonResult(BuildCompactDiff(result))
	})
}
