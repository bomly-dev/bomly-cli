package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerVulnFixTool(s *server.MCPServer, mcpCtx MCPContext) {
	tool := mcplib.NewTool("bomly_vuln_fix_context",
		mcplib.WithDescription("Return actionable fix context for a vulnerability in a specific package. "+
			"Identifies the manifest file(s) to edit, which package to upgrade, and what version to use. "+
			"For transitive dependencies, identifies the direct ancestor that introduces the vulnerable package. "+
			"This tool always enriches with vulnerability data; no --enrich flag is needed."),
		mcplib.WithString("package",
			mcplib.Required(),
			mcplib.Description("Package name, qualified name, or PURL of the vulnerable package"),
		),
		mcplib.WithString("vuln_id",
			mcplib.Description("Vulnerability identifier (e.g. CVE-2024-12345, GHSA-xxxx-yyyy-zzzz, or an OSV ID). "+
				"When omitted, fix context is returned for all vulnerabilities affecting the package."),
		),
		mcplib.WithString("path", mcplib.Description("Filesystem path to scan (defaults to cwd)")),
	)
	s.AddTool(tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		pkg, err := req.RequireString("package")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		fixReq := VulnFixRequest{
			Package: pkg,
			VulnID:  req.GetString("vuln_id", ""),
			Path:    req.GetString("path", ""),
		}
		result, err := mcpCtx.Adapter.VulnFixContext(ctx, fixReq)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return jsonResult(result)
	})
}
