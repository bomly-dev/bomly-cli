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
			Package:   pkg,
			Path:      req.GetString("path", ""),
			Enrich:    req.GetBool("enrich", false),
			Audit:     req.GetBool("audit", false),
			Analyze:   req.GetBool("analyze", false),
			Recursive: req.GetBool("recursive", false),
			MaxDepth:  req.GetInt("max_depth", 0),
			Exclude:   req.GetString("exclude", ""),
		}
		result, err := mcpCtx.Adapter.RunExplain(ctx, explainReq)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return jsonResult(BuildCompactExplain(pkg, result))
	})
}
