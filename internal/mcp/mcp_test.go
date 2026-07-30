package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/mcp"
	"github.com/bomly-dev/bomly-cli/internal/output"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/mark3labs/mcp-go/client"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// mockAdapter is a test double for OptionsAdapter.
type mockAdapter struct {
	scanResult    mcp.ScanRunResult
	scanErr       error
	scanReq       mcp.ScanRequest
	explainResult mcp.ExplainRunResult
	explainErr    error
	explainReq    mcp.ExplainRequest
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
func (m *mockAdapter) RunExplain(_ context.Context, req mcp.ExplainRequest) (mcp.ExplainRunResult, error) {
	m.explainReq = req
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
	return newTestClientWithContext(t, mcp.Context{Adapter: adapter, Version: "test"})
}

func newTestClientWithContext(t *testing.T, serverContext mcp.Context) *client.Client {
	t.Helper()
	s := mcp.NewServer(serverContext)
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

func TestToolDescriptionsExplainRemediationWorkflow(t *testing.T) {
	c := newTestClient(t, &mockAdapter{})
	toolsResult, err := c.ListTools(context.Background(), mcplib.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	wantByTool := map[string][]string{
		"bomly_scan": {
			"direct-bump",
			"override_advice",
			"known-exploited",
			"enrich=true with audit=true",
			"use bomly_explain",
		},
		"bomly_explain": {
			"dependency paths",
			"requires enrich=true",
			"after bomly_scan",
		},
		"bomly_diff": {
			"override_advice",
			"persisted policy findings",
			"requires enrich=true",
		},
	}
	for _, tool := range toolsResult.Tools {
		for _, want := range wantByTool[tool.Name] {
			if !strings.Contains(tool.Description, want) {
				t.Errorf("%s description missing %q: %q", tool.Name, want, tool.Description)
			}
		}
		delete(wantByTool, tool.Name)
	}
	if len(wantByTool) != 0 {
		t.Fatalf("tools missing from description check: %#v", wantByTool)
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

func TestToolsDoNotEnableNetworkOrAnalysisByDefault(t *testing.T) {
	t.Run("scan", func(t *testing.T) {
		adapter := &mockAdapter{
			scanResult: mcp.ScanRunResult{
				Response: output.ScanResponse{Command: "scan"},
			},
		}
		c := newTestClient(t, adapter)
		result := callTool(t, c, "bomly_scan", map[string]any{
			"path": "../../untrusted\npath",
		})
		if result.IsError {
			t.Fatalf("unexpected tool error: %v", result.Content)
		}
		if adapter.scanReq.Enrich || adapter.scanReq.Audit || adapter.scanReq.Analyze {
			t.Fatalf("scan enabled optional work without permission: %#v", adapter.scanReq)
		}
	})

	t.Run("explain", func(t *testing.T) {
		adapter := &mockAdapter{
			explainResult: mcp.ExplainRunResult{
				Response: output.ExplainResponse{Command: "explain"},
			},
		}
		c := newTestClient(t, adapter)
		result := callTool(t, c, "bomly_explain", map[string]any{
			"package": "pkg:npm/example@1.0.0\nuntrusted",
		})
		if result.IsError {
			t.Fatalf("unexpected tool error: %v", result.Content)
		}
		if adapter.explainReq.Enrich || adapter.explainReq.Audit || adapter.explainReq.Analyze {
			t.Fatalf("explain enabled optional work without permission: %#v", adapter.explainReq)
		}
	})

	t.Run("diff", func(t *testing.T) {
		adapter := &mockAdapter{
			diffResult: mcp.DiffRunResult{
				Response: output.DiffResponse{Command: "diff"},
			},
		}
		c := newTestClient(t, adapter)
		result := callTool(t, c, "bomly_diff", map[string]any{
			"base": "main\nuntrusted",
			"head": "HEAD",
		})
		if result.IsError {
			t.Fatalf("unexpected tool error: %v", result.Content)
		}
		if adapter.diffReq.Enrich || adapter.diffReq.Audit || adapter.diffReq.Analyze {
			t.Fatalf("diff enabled optional work without permission: %#v", adapter.diffReq)
		}
	})
}

func TestScanTool_PropagatesPolicyArguments(t *testing.T) {
	adapter := &mockAdapter{scanResult: mcp.ScanRunResult{Response: output.ScanResponse{Command: "scan"}}}
	c := newTestClient(t, adapter)
	arguments := map[string]any{
		"path": "/tmp", "enrich": true, "audit": true, "fail_on": "high",
		"allow_vulnerability_ids": "GHSA-test", "allow_licenses": "MIT",
		"deny_licenses": "GPL-3.0-only", "license_exempt_packages": "pkg:npm/example",
		"deny_packages": "pkg:npm/blocked", "deny_groups": "pkg:maven/com.example",
		"protected_packages": "react", "typosquat_threshold": "0.91",
		"typosquat_mode": "fail", "warn_only": true, "baseline": "security/baseline.json",
	}
	if result := callTool(t, c, "bomly_scan", arguments); result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	want := mcp.ScanRequest{
		Path: "/tmp", Enrich: true, Audit: true, FailOn: "high",
		AllowVulnerabilityIDs: "GHSA-test", AllowLicenses: "MIT",
		DenyLicenses: "GPL-3.0-only", LicenseExemptPackages: "pkg:npm/example",
		DenyPackages: "pkg:npm/blocked", DenyGroups: "pkg:maven/com.example",
		ProtectedPackages: "react", TyposquatThreshold: "0.91",
		TyposquatMode: "fail", WarnOnly: true, Baseline: "security/baseline.json",
	}
	if !reflect.DeepEqual(adapter.scanReq, want) {
		t.Fatalf("ScanRequest = %#v, want %#v", adapter.scanReq, want)
	}
}

func TestScanTool_PropagatesAdapterError(t *testing.T) {
	adapter := &mockAdapter{scanErr: errors.New("scan failed")}
	c := newTestClient(t, adapter)
	result := callTool(t, c, "bomly_scan", nil)
	if !result.IsError {
		t.Fatal("expected tool error, got success")
	}
	if got := toolResultText(t, result); got != "scan failed" {
		t.Fatalf("tool error = %q, want %q", got, "scan failed")
	}
}

func TestToolErrorsDoNotExposeAdapterDetails(t *testing.T) {
	const secret = "token=client-facing-secret"
	tests := []struct {
		name      string
		tool      string
		arguments map[string]any
		adapter   *mockAdapter
		want      string
	}{
		{
			name: "scan", tool: "bomly_scan",
			adapter: &mockAdapter{scanErr: errors.New("request to https://user:" + secret + "@example.test failed")},
			want:    "scan failed",
		},
		{
			name: "explain", tool: "bomly_explain",
			arguments: map[string]any{"package": "example"},
			adapter:   &mockAdapter{explainErr: errors.New("read /tmp/" + secret)},
			want:      "explain failed",
		},
		{
			name: "diff", tool: "bomly_diff",
			arguments: map[string]any{"base": "main", "head": "HEAD"},
			adapter:   &mockAdapter{diffErr: errors.New("run command with " + secret)},
			want:      "diff failed",
		},
		{
			name: "plugins", tool: "bomly_plugins",
			adapter: &mockAdapter{pluginsErr: errors.New("plugin config contains " + secret)},
			want:    "plugins failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTestClient(t, test.adapter)
			result := callTool(t, c, test.tool, test.arguments)
			if !result.IsError {
				t.Fatal("expected tool error, got success")
			}
			got := toolResultText(t, result)
			if got != test.want {
				t.Fatalf("tool error = %q, want %q", got, test.want)
			}
			if strings.Contains(got, secret) {
				t.Fatalf("tool error exposed adapter detail: %q", got)
			}
		})
	}
}

func TestToolErrorsExposeOnlyStableCategories(t *testing.T) {
	const secret = "category-secret"
	tests := []struct {
		name string
		kind mcp.ToolErrorKind
		want string
	}{
		{name: "request", kind: mcp.ToolErrorRequest, want: "scan request is invalid"},
		{name: "preparation", kind: mcp.ToolErrorPreparation, want: "scan target preparation failed"},
		{name: "target resolution", kind: mcp.ToolErrorTargetResolution, want: "scan target resolution failed"},
		{name: "pipeline", kind: mcp.ToolErrorPipeline, want: "scan pipeline failed"},
		{name: "plugin inventory", kind: mcp.ToolErrorPluginInventory, want: "plugin inventory failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := &mockAdapter{
				scanErr: mcp.WrapToolError(test.kind, errors.New(secret)),
			}
			c := newTestClient(t, adapter)
			result := callTool(t, c, "bomly_scan", nil)
			if got := toolResultText(t, result); got != test.want {
				t.Fatalf("tool error = %q, want %q", got, test.want)
			}
		})
	}
}

func TestWrapToolErrorPreservesInternalCause(t *testing.T) {
	cause := errors.New("internal cause")
	err := mcp.WrapToolError(mcp.ToolErrorPipeline, cause)
	if !errors.Is(err, cause) {
		t.Fatalf("WrapToolError() did not preserve cause: %v", err)
	}
}

func TestToolErrorLogsDoNotExposeAdapterDetails(t *testing.T) {
	const secret = "server-log-secret"
	core, observed := observer.New(zap.DebugLevel)
	adapter := &mockAdapter{
		scanErr: mcp.WrapToolError(
			mcp.ToolErrorPipeline,
			errors.New("subprocess failed with "+secret),
		),
	}
	c := newTestClientWithContext(t, mcp.Context{
		Adapter: adapter,
		Version: "test",
		Logger:  zap.New(core),
	})
	result := callTool(t, c, "bomly_scan", nil)
	if !result.IsError {
		t.Fatal("expected tool error, got success")
	}
	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("log entries = %d, want 1: %#v", len(entries), entries)
	}
	context := entries[0].ContextMap()
	if context["tool"] != "scan" || context["category"] != string(mcp.ToolErrorPipeline) {
		t.Fatalf("log context = %#v", context)
	}
	if context["cause_type"] != "*errors.errorString" {
		t.Fatalf("cause type = %#v, want *errors.errorString", context["cause_type"])
	}
	if strings.Contains(entries[0].Message, secret) ||
		strings.Contains(context["cause_type"].(string), secret) {
		t.Fatalf("server log exposed adapter detail: %#v", entries[0])
	}
}

func toolResultText(t *testing.T, result *mcplib.CallToolResult) string {
	t.Helper()
	if len(result.Content) != 1 {
		t.Fatalf("tool result content = %#v", result.Content)
	}
	text, ok := result.Content[0].(mcplib.TextContent)
	if !ok {
		t.Fatalf("tool result content type = %T", result.Content[0])
	}
	return text.Text
}

func TestExplainTool_RequiresPackage(t *testing.T) {
	c := newTestClient(t, &mockAdapter{})
	result := callTool(t, c, "bomly_explain", nil)
	if !result.IsError {
		t.Fatal("expected error when package arg is missing")
	}
}

func TestExplainTool_PropagatesPolicyArguments(t *testing.T) {
	adapter := &mockAdapter{explainResult: mcp.ExplainRunResult{Response: output.ExplainResponse{Command: "explain"}}}
	c := newTestClient(t, adapter)
	arguments := map[string]any{
		"package": "lodash", "audit": true, "fail_on": "medium",
		"allow_vulnerability_ids": "GHSA-test", "allow_licenses": "Apache-2.0",
		"deny_licenses": "AGPL-3.0-only", "license_exempt_packages": "pkg:npm/example",
		"deny_packages": "pkg:npm/blocked", "deny_groups": "pkg:maven/com.example",
		"protected_packages": "express", "typosquat_threshold": "0.92",
		"typosquat_mode": "warn", "warn_only": true, "baseline": "none",
	}
	if result := callTool(t, c, "bomly_explain", arguments); result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	want := mcp.ExplainRequest{
		Package: "lodash", Audit: true, FailOn: "medium",
		AllowVulnerabilityIDs: "GHSA-test", AllowLicenses: "Apache-2.0",
		DenyLicenses: "AGPL-3.0-only", LicenseExemptPackages: "pkg:npm/example",
		DenyPackages: "pkg:npm/blocked", DenyGroups: "pkg:maven/com.example",
		ProtectedPackages: "express", TyposquatThreshold: "0.92",
		TyposquatMode: "warn", WarnOnly: true, Baseline: "none",
	}
	if !reflect.DeepEqual(adapter.explainReq, want) {
		t.Fatalf("ExplainRequest = %#v, want %#v", adapter.explainReq, want)
	}
}

func TestExplainTool_ReturnsCompactJSONResult(t *testing.T) {
	adapter := &mockAdapter{
		explainResult: mcp.ExplainRunResult{
			Response: output.ExplainResponse{
				Command: "explain",
				Query:   output.ExplainQuery{Name: "lodash"},
				Targets: []output.ExplainTargetResponse{{
					Dependency: output.ExplainDependency{PackageRef: output.PackageRef{Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20"}},
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

func TestDiffToolPropagatesSourceChangePolicy(t *testing.T) {
	adapter := &mockAdapter{diffResult: mcp.DiffRunResult{Response: output.DiffResponse{Command: "diff"}}}
	client := newTestClient(t, adapter)
	result := callTool(t, client, "bomly_diff", map[string]any{
		"base":    "main",
		"head":    "HEAD",
		"enrich":  true,
		"audit":   true,
		"fail_on": "source-change",
	})
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if adapter.diffReq.FailOn != "source-change" {
		t.Fatalf("diff fail-on policy = %q", adapter.diffReq.FailOn)
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

func TestTools_PropagateRecursiveDiscoveryArgs(t *testing.T) {
	args := map[string]any{"recursive": true, "max_depth": 2, "exclude": "fixtures/*,dist"}

	adapter := &mockAdapter{scanResult: mcp.ScanRunResult{Response: output.ScanResponse{Command: "scan"}}}
	c := newTestClient(t, adapter)
	if result := callTool(t, c, "bomly_scan", args); result.IsError {
		t.Fatalf("unexpected scan tool error: %v", result.Content)
	}
	if !adapter.scanReq.Recursive || adapter.scanReq.MaxDepth != 2 || adapter.scanReq.Exclude != "fixtures/*,dist" {
		t.Fatalf("scan request missing recursive args: %#v", adapter.scanReq)
	}

	adapter = &mockAdapter{explainResult: mcp.ExplainRunResult{Response: output.ExplainResponse{Command: "explain"}}}
	c = newTestClient(t, adapter)
	explainArgs := map[string]any{"package": "lodash"}
	for k, v := range args {
		explainArgs[k] = v
	}
	if result := callTool(t, c, "bomly_explain", explainArgs); result.IsError {
		t.Fatalf("unexpected explain tool error: %v", result.Content)
	}
	if !adapter.explainReq.Recursive || adapter.explainReq.MaxDepth != 2 || adapter.explainReq.Exclude != "fixtures/*,dist" {
		t.Fatalf("explain request missing recursive args: %#v", adapter.explainReq)
	}

	adapter = &mockAdapter{diffResult: mcp.DiffRunResult{Response: output.DiffResponse{Command: "diff"}}}
	c = newTestClient(t, adapter)
	diffArgs := map[string]any{"base": "main", "head": "HEAD"}
	for k, v := range args {
		diffArgs[k] = v
	}
	if result := callTool(t, c, "bomly_diff", diffArgs); result.IsError {
		t.Fatalf("unexpected diff tool error: %v", result.Content)
	}
	if !adapter.diffReq.Recursive || adapter.diffReq.MaxDepth != 2 || adapter.diffReq.Exclude != "fixtures/*,dist" {
		t.Fatalf("diff request missing recursive args: %#v", adapter.diffReq)
	}
}
