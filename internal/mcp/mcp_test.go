package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/mcp"
	"github.com/bomly-dev/bomly-cli/internal/output"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/mark3labs/mcp-go/client"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// mockAdapter is a test double for OptionsAdapter.
type mockAdapter struct {
	scanResult    output.ScanResponse
	scanErr       error
	scanReq       mcp.ScanRequest
	explainResult output.ExplainResponse
	explainErr    error
	diffResult    output.DiffResponse
	diffErr       error
	plugins       []managedplugin.PluginInfo
	pluginsErr    error
	fixResult     mcp.VulnFixResult
	fixErr        error
}

func (m *mockAdapter) RunScan(_ context.Context, req mcp.ScanRequest) (output.ScanResponse, error) {
	m.scanReq = req
	return m.scanResult, m.scanErr
}
func (m *mockAdapter) RunExplain(_ context.Context, _ mcp.ExplainRequest) (output.ExplainResponse, error) {
	return m.explainResult, m.explainErr
}
func (m *mockAdapter) RunDiff(_ context.Context, _ mcp.DiffRequest) (output.DiffResponse, error) {
	return m.diffResult, m.diffErr
}
func (m *mockAdapter) ListPlugins(_ context.Context) (managedplugin.PluginListResponse, error) {
	return managedplugin.GroupPluginInfos(m.plugins), m.pluginsErr
}
func (m *mockAdapter) VulnFixContext(_ context.Context, _ mcp.VulnFixRequest) (mcp.VulnFixResult, error) {
	return m.fixResult, m.fixErr
}

func newTestClient(t *testing.T, adapter mcp.OptionsAdapter) *client.Client {
	t.Helper()
	s := mcp.NewServer(mcp.MCPContext{Adapter: adapter, Version: "test"})
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

func TestNewServer_RegistersFiveTools(t *testing.T) {
	c := newTestClient(t, &mockAdapter{})
	toolsResult, err := c.ListTools(context.Background(), mcplib.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	expected := []string{"bomly_scan", "bomly_explain", "bomly_diff", "bomly_vuln_fix_context", "bomly_plugins"}
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

func TestScanTool_ReturnsJSONResult(t *testing.T) {
	adapter := &mockAdapter{
		scanResult: output.ScanResponse{Command: "scan", SchemaVersion: "1"},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_scan", map[string]any{"path": "/tmp"})

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Fatal("empty content")
	}
	var resp output.ScanResponse
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Command != "scan" {
		t.Errorf("Command = %q, want %q", resp.Command, "scan")
	}
}

func TestScanTool_PropagatesScope(t *testing.T) {
	adapter := &mockAdapter{
		scanResult: output.ScanResponse{Command: "scan", SchemaVersion: "1"},
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

func TestExplainTool_ReturnsJSONResult(t *testing.T) {
	adapter := &mockAdapter{
		explainResult: output.ExplainResponse{Command: "explain", Query: output.ExplainQuery{Name: "lodash"}},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_explain", map[string]any{"package": "lodash"})

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	var resp output.ExplainResponse
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Query.Name != "lodash" {
		t.Errorf("Query.Name = %q, want %q", resp.Query.Name, "lodash")
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

func TestDiffTool_ReturnsJSONResult(t *testing.T) {
	adapter := &mockAdapter{
		diffResult: output.DiffResponse{Command: "diff"},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_diff", map[string]any{"base": "main", "head": "HEAD"})

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	var resp output.DiffResponse
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Command != "diff" {
		t.Errorf("Command = %q, want %q", resp.Command, "diff")
	}
}

func TestPluginsTool_ReturnsJSONResult(t *testing.T) {
	adapter := &mockAdapter{
		plugins: []managedplugin.PluginInfo{
			{Manifest: managedplugin.Manifest{Kind: "detector"}, BuiltIn: true, Enabled: true},
		},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_plugins", nil)

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	var resp managedplugin.PluginListResponse
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Detectors) != 1 {
		t.Errorf("len(resp.Detectors) = %d, want 1", len(resp.Detectors))
	}
}

func TestVulnFixTool_RequiresPackage(t *testing.T) {
	c := newTestClient(t, &mockAdapter{})
	r := callTool(t, c, "bomly_vuln_fix_context", map[string]any{"vuln_id": "CVE-2024-1234"})
	if !r.IsError {
		t.Error("expected error when package is missing")
	}
}

func TestVulnFixTool_ReturnsJSONResult(t *testing.T) {
	adapter := &mockAdapter{
		fixResult: mcp.VulnFixResult{
			Package:        output.PackageRef{Name: "lodash", Version: "4.17.20"},
			MinSafeVersion: "4.17.21",
			Vulnerabilities: []output.VulnerabilityRef{
				{ID: "CVE-2024-1234", FixedIn: "4.17.21"},
			},
			Recommendation: "Upgrade lodash",
		},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_vuln_fix_context", map[string]any{
		"package": "lodash",
		"vuln_id": "CVE-2024-1234",
	})

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	var resp mcp.VulnFixResult
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.MinSafeVersion != "4.17.21" {
		t.Errorf("MinSafeVersion = %q, want %q", resp.MinSafeVersion, "4.17.21")
	}
}

func TestVulnFixTool_AllVulnsWhenVulnIDOmitted(t *testing.T) {
	adapter := &mockAdapter{
		fixResult: mcp.VulnFixResult{
			Package:        output.PackageRef{Name: "lodash", Version: "4.17.20"},
			MinSafeVersion: "4.17.22",
			Vulnerabilities: []output.VulnerabilityRef{
				{ID: "CVE-2024-1111", FixedIn: "4.17.21"},
				{ID: "CVE-2024-2222", FixedIn: "4.17.22"},
			},
			Recommendation: "Upgrade lodash to 4.17.22",
		},
	}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_vuln_fix_context", map[string]any{
		"package": "lodash",
		// vuln_id intentionally omitted
	})

	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	var resp mcp.VulnFixResult
	text := result.Content[0].(mcplib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Vulnerabilities) != 2 {
		t.Errorf("len(Vulnerabilities) = %d, want 2", len(resp.Vulnerabilities))
	}
	if resp.MinSafeVersion != "4.17.22" {
		t.Errorf("MinSafeVersion = %q, want %q", resp.MinSafeVersion, "4.17.22")
	}
}

func TestBuildManifestFixTargets_DirectDependency(t *testing.T) {
	dep := output.PackageRef{ID: "lodash@4.17.20", Name: "lodash", Version: "4.17.20"}
	paths := []output.DependencyPath{
		{
			Relationship: "direct",
			Packages:     []output.PackageRef{{ID: "root"}, dep},
		},
	}
	manifests := []output.ScanManifest{
		{
			Path:           "package.json",
			Kind:           "npm-package",
			PackageManager: "npm",
			Packages: []output.ScanPackage{
				{PackageRef: dep},
			},
		},
	}

	targets := mcp.BuildManifestFixTargets(dep, paths, "4.17.21", manifests)

	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	got := targets[0]
	if got.ManifestPath != "package.json" {
		t.Errorf("ManifestPath = %q, want %q", got.ManifestPath, "package.json")
	}
	if got.RecommendedVersion != "4.17.21" {
		t.Errorf("RecommendedVersion = %q, want %q", got.RecommendedVersion, "4.17.21")
	}
	if got.ChangeType != "upgrade" {
		t.Errorf("ChangeType = %q, want %q", got.ChangeType, "upgrade")
	}
}

func TestBuildManifestFixTargets_TransitiveDependency(t *testing.T) {
	dep := output.PackageRef{ID: "lodash@4.17.20", Name: "lodash", Version: "4.17.20"}
	directDep := output.PackageRef{ID: "webpack@5.0.0", Name: "webpack", Version: "5.0.0"}
	paths := []output.DependencyPath{
		{
			Relationship: "transitive",
			Packages:     []output.PackageRef{{ID: "root"}, directDep, dep},
		},
	}
	manifests := []output.ScanManifest{
		{
			Path:           "package.json",
			PackageManager: "npm",
			Packages: []output.ScanPackage{
				{PackageRef: directDep},
			},
		},
	}

	targets := mcp.BuildManifestFixTargets(dep, paths, "4.17.21", manifests)

	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	got := targets[0]
	if got.TargetPackage != "webpack" {
		t.Errorf("TargetPackage = %q, want %q", got.TargetPackage, "webpack")
	}
	// No recommended version for transitive (we don't know which ancestor version fixes it)
	if got.RecommendedVersion != "" {
		t.Errorf("RecommendedVersion = %q, want empty for transitive", got.RecommendedVersion)
	}
}

func TestBuildManifestFixTargets_Deduplication(t *testing.T) {
	dep := output.PackageRef{ID: "lodash@4.17.20", Name: "lodash", Version: "4.17.20"}
	paths := []output.DependencyPath{
		{Relationship: "direct", Packages: []output.PackageRef{{ID: "root"}, dep}},
		{Relationship: "direct", Packages: []output.PackageRef{{ID: "root2"}, dep}},
	}
	manifests := []output.ScanManifest{
		{
			Path:     "package.json",
			Packages: []output.ScanPackage{{PackageRef: dep}},
		},
	}

	targets := mcp.BuildManifestFixTargets(dep, paths, "4.17.21", manifests)
	if len(targets) != 1 {
		t.Errorf("expected deduplication: got %d targets, want 1", len(targets))
	}
}

func TestBuildRecommendationText_Direct(t *testing.T) {
	dep := output.PackageRef{Name: "lodash", Version: "4.17.20"}
	targets := []mcp.ManifestFixTarget{
		{
			ManifestPath:       "package.json",
			TargetPackage:      "lodash",
			CurrentVersion:     "4.17.20",
			RecommendedVersion: "4.17.21",
		},
	}

	rec := mcp.BuildRecommendationText(dep, []string{"CVE-2024-1234"}, "4.17.21", targets)
	if rec == "" {
		t.Error("expected non-empty recommendation")
	}
}

func TestBuildRecommendationText_MultipleVulns(t *testing.T) {
	dep := output.PackageRef{Name: "lodash", Version: "4.17.20"}
	targets := []mcp.ManifestFixTarget{
		{
			ManifestPath:       "package.json",
			TargetPackage:      "lodash",
			CurrentVersion:     "4.17.20",
			RecommendedVersion: "4.17.22",
		},
	}

	rec := mcp.BuildRecommendationText(dep, []string{"CVE-2024-1111", "CVE-2024-2222"}, "4.17.22", targets)
	if rec == "" {
		t.Error("expected non-empty recommendation")
	}
	if !strings.Contains(rec, "CVE-2024-1111") || !strings.Contains(rec, "CVE-2024-2222") {
		t.Errorf("recommendation should mention all vuln IDs, got: %s", rec)
	}
}

func TestBuildRecommendationText_NoTargets(t *testing.T) {
	dep := output.PackageRef{Name: "lodash", Version: "4.17.20"}

	rec := mcp.BuildRecommendationText(dep, []string{"CVE-2024-1234"}, "4.17.21", nil)
	if rec == "" {
		t.Error("expected non-empty fallback recommendation")
	}
}
