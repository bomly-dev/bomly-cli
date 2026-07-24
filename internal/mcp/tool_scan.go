package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerScanTool(s *server.MCPServer, mcpCtx Context) {
	tool := mcplib.NewTool("bomly_scan",
		mcplib.WithDescription("Scan a project for dependencies and vulnerabilities. With enrich=true, the compact response groups vulnerable packages by the change that may address them. With audit=true, it also includes policy results. Use bomly_explain for full details about one package, or the CLI JSON format for the complete scan document."),
		mcplib.WithString("path", mcplib.Description("Filesystem path to scan (defaults to cwd)")),
		mcplib.WithString("image", mcplib.Description("Container image reference to scan (e.g. alpine:latest)")),
		mcplib.WithString("container", mcplib.Description("Deprecated alias for image")),
		mcplib.WithString("url", mcplib.Description("Git repository URL to clone and scan")),
		mcplib.WithString("ref", mcplib.Description("Git ref to checkout when using url")),
		mcplib.WithBoolean("enrich", mcplib.Description("Enrich packages with vulnerability and license data from external sources")),
		mcplib.WithBoolean("audit", mcplib.Description("Evaluate policy and produce findings from enriched vulnerability data (requires enrich)")),
		mcplib.WithBoolean("analyze", mcplib.Description("[Experimental] Run code analysis to confirm whether vulnerabilities are reachable from application code (requires enrich)")),
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
		mcplib.WithString("ecosystems", mcplib.Description("Ecosystem filter; supports +name/-name modifiers")),
		mcplib.WithString("scope", mcplib.Description("Filter dependencies by scope: runtime or development")),
		mcplib.WithBoolean("recursive", mcplib.Description("Recursively discover nested manifests under the scan root (monorepos); not valid with image")),
		mcplib.WithNumber("max_depth", mcplib.Description("Maximum directory depth for recursive discovery, counted from the scan root; defaults to 3, use a large value for effectively unlimited (requires recursive)")),
		mcplib.WithString("exclude", mcplib.Description("Comma-separated glob patterns relative to the scan root excluded from recursive discovery, in addition to built-in ignore rules (requires recursive)")),
	)
	s.AddTool(tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		scanReq := ScanRequest{
			Path:                  req.GetString("path", ""),
			Image:                 firstNonEmpty(req.GetString("image", ""), req.GetString("container", "")),
			URL:                   req.GetString("url", ""),
			Ref:                   req.GetString("ref", ""),
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
			Ecosystems:            req.GetString("ecosystems", ""),
			Scope:                 req.GetString("scope", ""),
			Recursive:             req.GetBool("recursive", false),
			MaxDepth:              req.GetInt("max_depth", 0),
			Exclude:               req.GetString("exclude", ""),
		}
		result, err := mcpCtx.Adapter.RunScan(ctx, scanReq)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return jsonResult(BuildCompactScan(result))
	})
}
