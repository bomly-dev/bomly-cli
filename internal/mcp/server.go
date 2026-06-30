package mcp

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ScanRequest holds per-call overrides for the bomly_scan tool.
type ScanRequest struct {
	Path       string `json:"path"`
	Image      string `json:"image"`
	URL        string `json:"url"`
	Ref        string `json:"ref"`
	Enrich     bool   `json:"enrich"`
	Audit      bool   `json:"audit"`
	Analyze    bool   `json:"analyze"`
	FailOn     string `json:"fail_on"`
	Ecosystems string `json:"ecosystems"`
	Scope      string `json:"scope"`
}

// ExplainRequest holds per-call overrides for the bomly_explain tool.
type ExplainRequest struct {
	Package string `json:"package"`
	Path    string `json:"path"`
	Enrich  bool   `json:"enrich"`
	Audit   bool   `json:"audit"`
	Analyze bool   `json:"analyze"`
}

// DiffRequest holds per-call overrides for the bomly_diff tool.
type DiffRequest struct {
	Base                  string `json:"base"`
	Head                  string `json:"head"`
	Path                  string `json:"path"`
	Image                 string `json:"image"`
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
}

// VulnFixRequest holds per-call overrides for the bomly_vuln_fix_context tool.
type VulnFixRequest struct {
	Package string `json:"package"`
	VulnID  string `json:"vuln_id"`
	Path    string `json:"path"`
}

// ManifestFixTarget describes one actionable change an agent can make to fix a vulnerability.
type ManifestFixTarget struct {
	ManifestPath       string `json:"manifest_path"`
	ManifestKind       string `json:"manifest_kind"`
	PackageManager     string `json:"package_manager"`
	TargetPackage      string `json:"target_package"`
	CurrentVersion     string `json:"current_version"`
	RecommendedVersion string `json:"recommended_version"`
	ChangeType         string `json:"change_type"`
}

// VulnFixResult is returned by the bomly_vuln_fix_context tool.
// Vulnerabilities holds all matched vulnerabilities (one when vuln_id was specified, all otherwise).
// MinSafeVersion is the minimum version that addresses every matched vulnerability.
type VulnFixResult struct {
	Package           output.PackageRef         `json:"package"`
	Vulnerabilities   []output.VulnerabilityRef `json:"vulnerabilities"`
	MinSafeVersion    string                    `json:"min_safe_version,omitempty"`
	AffectedManifests []ManifestFixTarget       `json:"affected_manifests"`
	Paths             []output.DependencyPath   `json:"paths"`
	Recommendation    string                    `json:"recommendation"`
}

// OptionsAdapter is implemented by the CLI adapter in internal/cli/mcp_cmd.go.
// It lives in package cli so it can access unexported pipeline helpers.
type OptionsAdapter interface {
	RunScan(ctx context.Context, req ScanRequest) (output.ScanResponse, error)
	RunExplain(ctx context.Context, req ExplainRequest) (output.ExplainResponse, error)
	RunDiff(ctx context.Context, req DiffRequest) (output.DiffResponse, error)
	ListPlugins(ctx context.Context) (managedplugin.ListResponse, error)
	VulnFixContext(ctx context.Context, req VulnFixRequest) (VulnFixResult, error)
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
	registerVulnFixTool(s, mcpCtx)
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

// BuildManifestFixTargets maps dependency paths back to actionable manifest edits.
// For direct dependencies, the manifest containing the vulnerable package is targeted.
// For transitive dependencies, the manifest containing the direct ancestor is targeted.
// minSafeVersion is the minimum version that fixes all matched vulnerabilities; it is used
// as the RecommendedVersion for direct dependencies (empty string for transitive).
func BuildManifestFixTargets(
	dependency output.PackageRef,
	paths []output.DependencyPath,
	minSafeVersion string,
	manifests []output.ScanManifest,
) []ManifestFixTarget {
	seen := make(map[string]bool)
	targets := make([]ManifestFixTarget, 0)

	for _, path := range paths {
		if len(path.Packages) < 2 {
			continue
		}

		var targetInManifest output.PackageRef
		isDirect := path.Relationship == "direct"

		if isDirect {
			targetInManifest = dependency
		} else {
			targetInManifest = path.Packages[1]
		}

		for _, manifest := range manifests {
			for _, pkg := range manifest.Dependencies {
				if pkg.ID != targetInManifest.ID {
					continue
				}
				key := manifest.Path + "::" + targetInManifest.ID
				if seen[key] {
					break
				}
				seen[key] = true

				recommendedVersion := ""
				if isDirect {
					recommendedVersion = minSafeVersion
				}

				targets = append(targets, ManifestFixTarget{
					ManifestPath:       manifest.Path,
					ManifestKind:       string(manifest.Kind),
					PackageManager:     manifest.PackageManager.Name(),
					TargetPackage:      targetInManifest.Name,
					CurrentVersion:     targetInManifest.Version,
					RecommendedVersion: recommendedVersion,
					ChangeType:         "upgrade",
				})
				break
			}
		}
	}

	return targets
}

// BuildRecommendationText produces a human-readable summary for an AI agent.
// vulnIDs lists all vulnerability identifiers being addressed.
// minSafeVersion is the minimum version that fixes all of them (may be empty if unknown).
func BuildRecommendationText(
	dependency output.PackageRef,
	vulnIDs []string,
	minSafeVersion string,
	targets []ManifestFixTarget,
) string {
	vulnLabel := strings.Join(vulnIDs, ", ")

	if len(targets) == 0 {
		msg := vulnLabel + " affects " + dependency.Name + "@" + dependency.Version
		if minSafeVersion != "" {
			msg += ". A fix is available in version " + minSafeVersion
		} else {
			msg += ". No fixed version is available at this time"
		}
		msg += ". No manifest file could be identified for automated remediation."
		return msg
	}

	t := targets[0]
	if t.RecommendedVersion != "" {
		return "Upgrade `" + t.TargetPackage + "` from " + t.CurrentVersion +
			" to " + t.RecommendedVersion +
			" in " + t.ManifestPath +
			" to fix " + vulnLabel + " affecting " + dependency.Name + "@" + dependency.Version + "."
	}
	suffix := ""
	if minSafeVersion != "" {
		suffix = " (fixed in " + minSafeVersion + ")"
	}
	return vulnLabel + " in `" + dependency.Name + "@" + dependency.Version +
		"` is a transitive dependency introduced via `" + t.TargetPackage + "@" + t.CurrentVersion + "`" +
		" in " + t.ManifestPath + "." +
		" Look for a newer version of `" + t.TargetPackage + "` that depends on a patched version of `" + dependency.Name + "`" +
		suffix + "."
}
