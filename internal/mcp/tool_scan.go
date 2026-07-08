package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerScanTool(s *server.MCPServer, mcpCtx Context) {
	tool := mcplib.NewTool("bomly_scan",
		mcplib.WithDescription("Scan a project for dependencies, vulnerabilities, and policy findings. Returns a compact, remediation-focused JSON summary sized for tool-result limits: vulnerable packages grouped by the concrete fix that closes them (which direct dependency to bump, in which manifest, to which version), plus coverage counts for everything omitted. For a security review pass audit=true and enrich=true. Drill into one package's full advisory detail with bomly_explain; for the complete scan document run `bomly scan --format json -o <file>` via the CLI instead of this tool."),
		mcplib.WithString("path", mcplib.Description("Filesystem path to scan (defaults to cwd)")),
		mcplib.WithString("image", mcplib.Description("Container image reference to scan (e.g. alpine:latest)")),
		mcplib.WithString("container", mcplib.Description("Deprecated alias for image")),
		mcplib.WithString("url", mcplib.Description("Git repository URL to clone and scan")),
		mcplib.WithString("ref", mcplib.Description("Git ref to checkout when using url")),
		mcplib.WithBoolean("enrich", mcplib.Description("Enrich packages with vulnerability and license data from external sources")),
		mcplib.WithBoolean("audit", mcplib.Description("Evaluate policy and produce findings from enriched vulnerability data (requires enrich)")),
		mcplib.WithBoolean("analyze", mcplib.Description("[Experimental] Run code analysis to confirm whether vulnerabilities are reachable from application code (requires enrich)")),
		mcplib.WithString("fail_on", mcplib.Description("Audit finding constraint: any, low, medium, high, critical, reachable, or exploitable")),
		mcplib.WithString("ecosystems", mcplib.Description("Ecosystem filter; supports +name/-name modifiers")),
		mcplib.WithString("scope", mcplib.Description("Filter dependencies by scope: runtime or development")),
	)
	s.AddTool(tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		scanReq := ScanRequest{
			Path:       req.GetString("path", ""),
			Image:      firstNonEmpty(req.GetString("image", ""), req.GetString("container", "")),
			URL:        req.GetString("url", ""),
			Ref:        req.GetString("ref", ""),
			Enrich:     req.GetBool("enrich", false),
			Audit:      req.GetBool("audit", false),
			Analyze:    req.GetBool("analyze", false),
			FailOn:     req.GetString("fail_on", ""),
			Ecosystems: req.GetString("ecosystems", ""),
			Scope:      req.GetString("scope", ""),
		}
		result, err := mcpCtx.Adapter.RunScan(ctx, scanReq)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return jsonResult(BuildCompactScan(result))
	})
}
