package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerPluginsTool(s *server.MCPServer, mcpCtx Context) {
	tool := mcplib.NewTool("bomly_plugins",
		mcplib.WithDescription("List all available bomly plugins (built-in detectors, matchers, and auditors plus any installed external plugins) with their enabled/disabled state."),
	)
	s.AddTool(tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		result, err := mcpCtx.Adapter.ListPlugins(ctx)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return jsonResult(result)
	})
}
