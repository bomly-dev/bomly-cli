package mcp

import (
	"context"
	"encoding/json"

	"github.com/bomly-dev/bomly-cli/internal/output"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/sdk"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ScanRequest holds per-call overrides for the bomly_scan tool.
type ScanRequest struct {
	Path                  string `json:"path"`
	Image                 string `json:"image"`
	URL                   string `json:"url"`
	Ref                   string `json:"ref"`
	Enrich                bool   `json:"enrich"`
	Audit                 bool   `json:"audit"`
	Analyze               bool   `json:"analyze"`
	FailOn                string `json:"fail_on"`
	AllowVulnerabilityIDs string `json:"allow_vulnerability_ids"`
	AllowLicenses         string `json:"allow_licenses"`
	DenyLicenses          string `json:"deny_licenses"`
	LicenseExemptPackages string `json:"license_exempt_packages"`
	DenyPackages          string `json:"deny_packages"`
	DenyGroups            string `json:"deny_groups"`
	ProtectedPackages     string `json:"protected_packages"`
	TyposquatThreshold    string `json:"typosquat_threshold"`
	TyposquatMode         string `json:"typosquat_mode"`
	WarnOnly              bool   `json:"warn_only"`
	Ecosystems            string `json:"ecosystems"`
	Scope                 string `json:"scope"`
	Recursive             bool   `json:"recursive"`
	MaxDepth              int    `json:"max_depth"`
	Exclude               string `json:"exclude"`
}

// ExplainRequest holds per-call overrides for the bomly_explain tool.
type ExplainRequest struct {
	Package               string `json:"package"`
	Path                  string `json:"path"`
	Enrich                bool   `json:"enrich"`
	Audit                 bool   `json:"audit"`
	Analyze               bool   `json:"analyze"`
	FailOn                string `json:"fail_on"`
	AllowVulnerabilityIDs string `json:"allow_vulnerability_ids"`
	AllowLicenses         string `json:"allow_licenses"`
	DenyLicenses          string `json:"deny_licenses"`
	LicenseExemptPackages string `json:"license_exempt_packages"`
	DenyPackages          string `json:"deny_packages"`
	DenyGroups            string `json:"deny_groups"`
	ProtectedPackages     string `json:"protected_packages"`
	TyposquatThreshold    string `json:"typosquat_threshold"`
	TyposquatMode         string `json:"typosquat_mode"`
	WarnOnly              bool   `json:"warn_only"`
	Recursive             bool   `json:"recursive"`
	MaxDepth              int    `json:"max_depth"`
	Exclude               string `json:"exclude"`
}

// DiffRequest holds per-call overrides for the bomly_diff tool.
type DiffRequest struct {
	Base                  string `json:"base"`
	Head                  string `json:"head"`
	Path                  string `json:"path"`
	Image                 string `json:"image"`
	SBOM                  bool   `json:"sbom"`
	Enrich                bool   `json:"enrich"`
	Audit                 bool   `json:"audit"`
	Analyze               bool   `json:"analyze"`
	FailOn                string `json:"fail_on"`
	AllowVulnerabilityIDs string `json:"allow_vulnerability_ids"`
	AllowLicenses         string `json:"allow_licenses"`
	DenyLicenses          string `json:"deny_licenses"`
	LicenseExemptPackages string `json:"license_exempt_packages"`
	DenyPackages          string `json:"deny_packages"`
	DenyGroups            string `json:"deny_groups"`
	ProtectedPackages     string `json:"protected_packages"`
	TyposquatThreshold    string `json:"typosquat_threshold"`
	TyposquatMode         string `json:"typosquat_mode"`
	WarnOnly              bool   `json:"warn_only"`
	Recursive             bool   `json:"recursive"`
	MaxDepth              int    `json:"max_depth"`
	Exclude               string `json:"exclude"`
}

// ScanRunResult carries a scan run's full output back to the MCP layer:
// the structured response plus the raw domain data (findings, graph,
// registry) the compact builders group and rank, and the pipeline
// diagnostics mapped by the adapter (internal/mcp never imports
// internal/engine).
type ScanRunResult struct {
	Response    output.ScanResponse
	Findings    []sdk.Finding
	Graph       *sdk.Graph
	Registry    *sdk.PackageRegistry
	Diagnostics []Diagnostic
	EnrichRan   bool
	AuditRan    bool
}

// ExplainRunResult carries an explain run's output plus the raw domain data
// the compact builders need to attach remediation context to the queried
// package.
type ExplainRunResult struct {
	Response    output.ExplainResponse
	Findings    []sdk.Finding
	Graph       *sdk.Graph
	Registry    *sdk.PackageRegistry
	Manifests   []output.ScanManifest
	Diagnostics []Diagnostic
	EnrichRan   bool
	AuditRan    bool
}

// DiffRunResult carries a diff run's output plus the audit delta buckets
// ([]sdk.Finding per bucket, computed version-independently by advisory id)
// and the head-side domain data used to build remediation context for what
// remains after merge.
type DiffRunResult struct {
	Response      output.DiffResponse
	Introduced    []sdk.Finding
	Resolved      []sdk.Finding
	Persisted     []sdk.Finding
	HeadGraph     *sdk.Graph
	HeadRegistry  *sdk.PackageRegistry
	BaseRegistry  *sdk.PackageRegistry
	HeadManifests []output.ScanManifest
	Diagnostics   []Diagnostic
	EnrichRan     bool
	AuditRan      bool
}

// OptionsAdapter is implemented by the CLI adapter in internal/cli/mcp_cmd.go.
// It lives in package cli so it can access unexported pipeline helpers.
type OptionsAdapter interface {
	RunScan(ctx context.Context, req ScanRequest) (ScanRunResult, error)
	RunExplain(ctx context.Context, req ExplainRequest) (ExplainRunResult, error)
	RunDiff(ctx context.Context, req DiffRequest) (DiffRunResult, error)
	ListPlugins(ctx context.Context) (managedplugin.ListResponse, error)
}

// Context carries the adapter and version into tool handlers.
type Context struct {
	Adapter OptionsAdapter
	Version string
}

// NewServer creates a configured MCP server with all bomly tools registered.
func NewServer(mcpCtx Context) *server.MCPServer {
	s := server.NewMCPServer(
		"bomly",
		mcpCtx.Version,
		server.WithToolCapabilities(false),
	)
	registerScanTool(s, mcpCtx)
	registerExplainTool(s, mcpCtx)
	registerDiffTool(s, mcpCtx)
	registerPluginsTool(s, mcpCtx)
	return s
}

// jsonResult marshals v to JSON and returns it as a text tool result.
// firstNonEmpty returns the first non-empty string, used to prefer a primary
// argument over a deprecated alias.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func jsonResult(v any) (*mcplib.CallToolResult, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return mcplib.NewToolResultError("marshal result: " + err.Error()), nil
	}
	return mcplib.NewToolResultText(string(data)), nil
}
