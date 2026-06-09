package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerDiffTool(s *server.MCPServer, mcpCtx Context) {
	tool := mcplib.NewTool("bomly_diff",
		mcplib.WithDescription("Compare dependency states between two Git refs. Returns added, removed, and changed packages with optional audit delta."),
		mcplib.WithString("base",
			mcplib.Required(),
			mcplib.Description("Base Git ref to compare (e.g. main, HEAD~1, a commit SHA)"),
		),
		mcplib.WithString("head",
			mcplib.Required(),
			mcplib.Description("Head Git ref to compare (e.g. HEAD, a branch name, a commit SHA)"),
		),
		mcplib.WithString("path", mcplib.Description("Local repository path (defaults to cwd)")),
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
		return jsonResult(result)
	})
}
