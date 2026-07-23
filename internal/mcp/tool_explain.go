package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerExplainTool(s *server.MCPServer, mcpCtx Context) {
	tool := mcplib.NewTool("bomly_explain",
		mcplib.WithDescription("Explain one package: root-to-target dependency paths, and — with enrich/audit — the FULL advisory detail (descriptions, references, CVSS, affected ranges) plus concrete fix context (which direct dependency to change, in which manifest, to which version, including override advice for transitive cases). This is the drill-down companion to bomly_scan: scan first for the compact overview, then explain each package you intend to fix. Pass enrich=true and audit=true to get advisories and remediation."),
		mcplib.WithString("package",
			mcplib.Required(),
			mcplib.Description("Package name, qualified name (org/name), or PURL to find"),
		),
		mcplib.WithString("path", mcplib.Description("Filesystem path to scan (defaults to cwd)")),
		mcplib.WithBoolean("enrich", mcplib.Description("Enrich packages with vulnerability and license data")),
		mcplib.WithBoolean("audit", mcplib.Description("Evaluate policy on the target package (requires enrich)")),
		mcplib.WithBoolean("analyze", mcplib.Description("Run code analysis to confirm whether vulnerabilities on the target package are reachable from application code (requires enrich)")),
		mcplib.WithString("fail_on", mcplib.Description("Audit finding constraint: any, low, medium, high, critical, reachable, or exploitable")),
		mcplib.WithString("allow_vulnerability_ids", mcplib.Description("Comma-separated vulnerability IDs to ignore during audit")),
		mcplib.WithString("allow_licenses", mcplib.Description("Comma-separated licenses allowed by policy")),
		mcplib.WithString("deny_licenses", mcplib.Description("Comma-separated licenses denied by policy")),
		mcplib.WithString("license_exempt_packages", mcplib.Description("Comma-separated package PURLs exempt from license policy")),
		mcplib.WithString("deny_packages", mcplib.Description("Comma-separated package PURLs denied by policy")),
		mcplib.WithString("deny_groups", mcplib.Description("Comma-separated package PURL namespaces denied by policy")),
		mcplib.WithString("protected_packages", mcplib.Description("Comma-separated package names to protect from typosquatting")),
		mcplib.WithString("typosquat_threshold", mcplib.Description("Typosquatting similarity threshold")),
		mcplib.WithString("typosquat_mode", mcplib.Description("Typosquatting mode: warn or fail")),
		mcplib.WithBoolean("warn_only", mcplib.Description("Downgrade failing findings to warnings")),
		mcplib.WithString("baseline", mcplib.Description("Finding baseline selection: auto, none, or a project-relative/absolute path")),
		mcplib.WithBoolean("recursive", mcplib.Description("Recursively discover nested manifests under the scan root (monorepos)")),
		mcplib.WithNumber("max_depth", mcplib.Description("Maximum directory depth for recursive discovery, counted from the scan root; defaults to 3, use a large value for effectively unlimited (requires recursive)")),
		mcplib.WithString("exclude", mcplib.Description("Comma-separated glob patterns relative to the scan root excluded from recursive discovery, in addition to built-in ignore rules (requires recursive)")),
	)
	s.AddTool(tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		pkg, err := req.RequireString("package")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		explainReq := ExplainRequest{
			Package:               pkg,
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
			Baseline:              req.GetString("baseline", ""),
			Recursive:             req.GetBool("recursive", false),
			MaxDepth:              req.GetInt("max_depth", 0),
			Exclude:               req.GetString("exclude", ""),
		}
		result, err := mcpCtx.Adapter.RunExplain(ctx, explainReq)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return jsonResult(BuildCompactExplain(pkg, result))
	})
}
