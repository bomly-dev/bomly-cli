package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerDiffTool(s *server.MCPServer, mcpCtx MCPContext) {
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
		mcplib.WithBoolean("reachability", mcplib.Description("Run code analysis on each side and include reachability annotations on the audit delta (requires enrich)")),
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
			Base:         base,
			Head:         head,
			Path:         req.GetString("path", ""),
			Enrich:       req.GetBool("enrich", false),
			Audit:        req.GetBool("audit", false),
			Reachability: req.GetBool("reachability", false),
		}
		result, err := mcpCtx.Adapter.RunDiff(ctx, diffReq)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return jsonResult(result)
	})
}
