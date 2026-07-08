package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/mcp"
	"github.com/bomly-dev/bomly-cli/internal/output"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/mark3labs/mcp-go/client"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// mockAdapter is a test double for OptionsAdapter.
type mockAdapter struct {
	scanResult    mcp.ScanRunResult
	scanErr       error
	scanReq       mcp.ScanRequest
	explainResult mcp.ExplainRunResult
	explainErr    error
	diffResult    mcp.DiffRunResult
	diffErr       error
	diffReq       mcp.DiffRequest
	plugins       []managedplugin.Info
	pluginsErr    error
}

func (m *mockAdapter) RunScan(_ context.Context, req mcp.ScanRequest) (mcp.ScanRunResult, error) {
	m.scanReq = req
	return m.scanResult, m.scanErr
}
func (m *mockAdapter) RunExplain(_ context.Context, _ mcp.ExplainRequest) (mcp.ExplainRunResult, error) {
	return m.explainResult, m.explainErr
}
func (m *mockAdapter) RunDiff(_ context.Context, req mcp.DiffRequest) (mcp.DiffRunResult, error) {
	m.diffReq = req
	return m.diffResult, m.diffErr
}
func (m *mockAdapter) ListPlugins(_ context.Context) (managedplugin.ListResponse, error) {
	return managedplugin.GroupPluginInfos(m.plugins), m.pluginsErr
}

func newTestClient(t *testing.T, adapter mcp.OptionsAdapter) *client.Client {
	t.Helper()
	s := mcp.NewServer(mcp.Context{Adapter: adapter, Version: "test"})
	c, err := client.NewInProcessClient(s)
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	_, err = c.Initialize(context.Background(), mcplib.InitializeRequest{})
	if err != nil {
		t.Fatalf("client.Initialize: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func callTool(t *testing.T, c *client.Client, name string, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	result, err := c.CallTool(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	})
	if err != nil {
		t.Fatalf("CallTool %q: %v", name, err)
	}
	return result
}

func TestNewServer_RegistersFourTools(t *testing.T) {
	c := newTestClient(t, &mockAdapter{})
	toolsResult, err := c.ListTools(context.Background(), mcplib.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	expected := []string{"bomly_scan", "bomly_explain", "bomly_diff", "bomly_plugins"}
	if len(toolsResult.Tools) != len(expected) {
		t.Errorf("got %d tools, want %d", len(toolsResult.Tools), len(expected))
	}
	names := make(map[string]bool, len(toolsResult.Tools))
	for _, tool := range toolsResult.Tools {
		names[tool.Name] = true
	}
	for _, want := range expected {
		if !names[want] {
			t.Errorf("tool %q not registered", want)
		}
	}
}

func TestScanTool_ReturnsCompactJSONResult(t *testing.T) {
	adapter := &mockAdapter{
		scanResult: mcp.ScanRunResult{
			Response: output.ScanResponse{Command: "scan", SchemaVersion: "1"},
		},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_scan", map[string]any{"path": "/tmp"})

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Fatal("empty content")
	}
	var resp mcp.CompactScanResponse
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Command != "scan" {
		t.Errorf("Command = %q, want %q", resp.Command, "scan")
	}
	if resp.SchemaVersion != mcp.CompactSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", resp.SchemaVersion, mcp.CompactSchemaVersion)
	}
}

func TestScanTool_PropagatesScope(t *testing.T) {
	adapter := &mockAdapter{
		scanResult: mcp.ScanRunResult{
			Response: output.ScanResponse{Command: "scan", SchemaVersion: "1"},
		},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_scan", map[string]any{"path": "/tmp", "scope": "runtime"})

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if adapter.scanReq.Scope != "runtime" {
		t.Fatalf("ScanRequest.Scope = %q, want runtime", adapter.scanReq.Scope)
	}
}

func TestScanTool_PropagatesAdapterError(t *testing.T) {
	adapter := &mockAdapter{scanErr: errors.New("scan failed")}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_scan", nil)
	if !result.IsError {
		t.Fatal("expected tool error, got success")
	}
}

func TestExplainTool_RequiresPackage(t *testing.T) {
	c := newTestClient(t, &mockAdapter{})
	result := callTool(t, c, "bomly_explain", nil)
	if !result.IsError {
		t.Fatal("expected error when package arg is missing")
	}
}

func TestExplainTool_ReturnsCompactJSONResult(t *testing.T) {
	adapter := &mockAdapter{
		explainResult: mcp.ExplainRunResult{
			Response: output.ExplainResponse{
				Command: "explain",
				Query:   output.ExplainQuery{Name: "lodash"},
				Targets: []output.ExplainTargetResponse{{
					Dependency: output.PackageRef{Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20"},
					Paths: []output.DependencyPath{{
						Relationship: "direct",
						Packages: []output.PackageRef{
							{Name: "app", Version: "1.0.0"},
							{Name: "lodash", Version: "4.17.20"},
						},
					}},
				}},
			},
		},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_explain", map[string]any{"package": "lodash"})

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	var resp mcp.CompactExplainResponse
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Query != "lodash" {
		t.Errorf("Query = %q, want %q", resp.Query, "lodash")
	}
	if len(resp.Matches) != 1 {
		t.Fatalf("expected one match, got %#v", resp.Matches)
	}
	match := resp.Matches[0]
	if match.Direct == nil || !*match.Direct {
		t.Fatalf("expected direct match, got %#v", match.Direct)
	}
	if len(match.Paths) != 1 || match.Paths[0][0] != "app@1.0.0" || match.Paths[0][1] != "lodash@4.17.20" {
		t.Fatalf("unexpected paths: %#v", match.Paths)
	}
}

func TestDiffTool_RequiresBaseAndHead(t *testing.T) {
	c := newTestClient(t, &mockAdapter{})

	// Missing head
	r1 := callTool(t, c, "bomly_diff", map[string]any{"base": "main"})
	if !r1.IsError {
		t.Error("expected error when head is missing")
	}

	// Missing base
	r2 := callTool(t, c, "bomly_diff", map[string]any{"head": "HEAD"})
	if !r2.IsError {
		t.Error("expected error when base is missing")
	}
}

func TestDiffTool_ReturnsCompactJSONResult(t *testing.T) {
	adapter := &mockAdapter{
		diffResult: mcp.DiffRunResult{
			Response: output.DiffResponse{
				Command:    "diff",
				Comparison: output.DiffComparison{Base: "main", Head: "HEAD"},
			},
			Resolved: []sdk.Finding{{
				ID: "GHSA-fixed", VulnerabilityID: "GHSA-fixed",
				Kind: sdk.FindingKindVulnerability, Severity: sdk.SeverityHigh,
				PackageRef: "pkg:npm/lib@1.0.0",
			}},
			AuditRan: true,
		},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_diff", map[string]any{"base": "main", "head": "HEAD"})

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	var resp mcp.CompactDiffResponse
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Command != "diff" || resp.Comparison.Base != "main" {
		t.Errorf("unexpected response header: %#v", resp)
	}
	if len(resp.SecurityDelta.Resolved) != 1 || resp.SecurityDelta.Resolved[0].VulnID != "GHSA-fixed" {
		t.Fatalf("resolved delta missing: %#v", resp.SecurityDelta)
	}
	if resp.Summary.Resolved != 1 {
		t.Fatalf("summary resolved count = %d", resp.Summary.Resolved)
	}
}

func TestDiffTool_PropagatesTargetSelectors(t *testing.T) {
	// The image, container-alias, and sbom selectors must reach the adapter
	// so it can dispatch to the container / SBOM resolvers instead of the
	// default Git path.
	cases := []struct {
		name      string
		args      map[string]any
		wantImage string
		wantSBOM  bool
	}{
		{"git default", map[string]any{"base": "main", "head": "HEAD"}, "", false},
		{"image", map[string]any{"base": "3.19", "head": "3.20", "image": "alpine"}, "alpine", false},
		{"container alias", map[string]any{"base": "3.19", "head": "3.20", "container": "alpine"}, "alpine", false},
		{"sbom", map[string]any{"base": "base.spdx.json", "head": "head.spdx.json", "sbom": true}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &mockAdapter{diffResult: mcp.DiffRunResult{Response: output.DiffResponse{Command: "diff"}}}
			c := newTestClient(t, adapter)
			result := callTool(t, c, "bomly_diff", tc.args)
			if result.IsError {
				t.Fatalf("unexpected tool error: %v", result.Content)
			}
			if adapter.diffReq.Image != tc.wantImage {
				t.Errorf("DiffRequest.Image = %q, want %q", adapter.diffReq.Image, tc.wantImage)
			}
			if adapter.diffReq.SBOM != tc.wantSBOM {
				t.Errorf("DiffRequest.SBOM = %v, want %v", adapter.diffReq.SBOM, tc.wantSBOM)
			}
		})
	}
}

func TestPluginsTool_ReturnsJSONResult(t *testing.T) {
	adapter := &mockAdapter{
		plugins: []managedplugin.Info{
			{Manifest: managedplugin.Manifest{Kind: "detector"}, BuiltIn: true},
		},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_plugins", nil)

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	var resp managedplugin.ListResponse
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Detectors) != 1 {
		t.Errorf("len(resp.Detectors) = %d, want 1", len(resp.Detectors))
	}
}
