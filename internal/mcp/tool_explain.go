package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerExplainTool(s *server.MCPServer, mcpCtx MCPContext) {
	tool := mcplib.NewTool("bomly_explain",
		mcplib.WithDescription("Explain why a dependency exists by returning all root-to-target paths through the dependency graph."),
		mcplib.WithString("package",
			mcplib.Required(),
			mcplib.Description("Package name, qualified name (org/name), or PURL to find"),
		),
		mcplib.WithString("path", mcplib.Description("Filesystem path to scan (defaults to cwd)")),
		mcplib.WithBoolean("enrich", mcplib.Description("Enrich packages with vulnerability and license data")),
		mcplib.WithBoolean("audit", mcplib.Description("Evaluate policy on the target package")),
	)
	s.AddTool(tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		pkg, err := req.RequireString("package")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		explainReq := ExplainRequest{
			Package: pkg,
			Path:    req.GetString("path", ""),
			Enrich:  req.GetBool("enrich", false),
			Audit:   req.GetBool("audit", false),
		}
		result, err := mcpCtx.Adapter.RunExplain(ctx, explainReq)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return jsonResult(result)
	})
}
