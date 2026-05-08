package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerScanTool(s *server.MCPServer, mcpCtx MCPContext) {
	tool := mcplib.NewTool("bomly_scan",
		mcplib.WithDescription("Scan a project for dependencies, vulnerabilities, and policy findings. Returns structured JSON with all packages, manifests, and optional audit results."),
		mcplib.WithString("path", mcplib.Description("Filesystem path to scan (defaults to cwd)")),
		mcplib.WithString("container", mcplib.Description("Container image reference to scan (e.g. alpine:latest)")),
		mcplib.WithString("url", mcplib.Description("Git repository URL to clone and scan")),
		mcplib.WithString("ref", mcplib.Description("Git ref to checkout when using url")),
		mcplib.WithBoolean("enrich", mcplib.Description("Enrich packages with vulnerability and license data from external sources")),
		mcplib.WithBoolean("audit", mcplib.Description("Evaluate policy and produce findings from enriched vulnerability data (requires enrich)")),
		mcplib.WithBoolean("reachability", mcplib.Description("Run code analysis to confirm whether vulnerabilities are reachable from application code (requires enrich)")),
		mcplib.WithString("fail_on", mcplib.Description("Minimum severity threshold for audit findings: any, low, medium, high, critical")),
		mcplib.WithString("ecosystems", mcplib.Description("Ecosystem filter; supports +name/-name modifiers")),
	)
	s.AddTool(tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		scanReq := ScanRequest{
			Path:         req.GetString("path", ""),
			Container:    req.GetString("container", ""),
			URL:          req.GetString("url", ""),
			Ref:          req.GetString("ref", ""),
			Enrich:       req.GetBool("enrich", false),
			Audit:        req.GetBool("audit", false),
			Reachability: req.GetBool("reachability", false),
			FailOn:       req.GetString("fail_on", ""),
			Ecosystems:   req.GetString("ecosystems", ""),
		}
		result, err := mcpCtx.Adapter.RunScan(ctx, scanReq)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return jsonResult(result)
	})
}
