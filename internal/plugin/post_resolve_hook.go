package plugin

import (
	"context"
	"fmt"

	"github.com/bomly/bomly-cli/internal/scan"
)

// PostResolveHook adapts a plugin with a post-resolve stage to scan.PostResolveHook.
type PostResolveHook struct {
	PluginPath  string
	PluginName  string
	Subcommand  string
	CoreVersion string
	Priority    int
	RunOpts     RunOptions
}

// Descriptor returns the hook metadata.
func (h PostResolveHook) Descriptor() scan.HookDescriptor {
	return scan.HookDescriptor{
		Name:     h.PluginName + "-post-resolve",
		Priority: h.Priority,
		Stage:    StagePostResolve,
	}
}

// Execute runs the plugin post-resolve stage via the JSON envelope protocol.
func (h PostResolveHook) Execute(_ context.Context, pctx scan.PostResolveContext) error {
	var packages []PackageInfo
	if g, err := pctx.Consolidated.Graphs.ConsolidatedGraph(); err == nil && g != nil {
		packages = packagesFromGraph(g)
	}

	findings := make([]FindingInfo, 0, len(pctx.Findings))
	for _, f := range pctx.Findings {
		findings = append(findings, FindingInfo{
			ID:       f.ID,
			Source:   f.Source,
			Severity: f.Severity,
			Summary:  f.Title,
		})
	}

	input := PostResolveInput{
		Packages: packages,
		Findings: findings,
	}

	env, err := RunWithEnvelope(h.PluginPath, h.Subcommand, StagePostResolve, input, pctx.Stderr, h.CoreVersion, h.RunOpts)
	if err != nil {
		return fmt.Errorf("plugin %s post-resolve: %w", h.PluginName, err)
	}

	output, err := DecodePayload[PostResolveOutput](env)
	if err != nil {
		return fmt.Errorf("plugin %s post-resolve: %w", h.PluginName, err)
	}
	if !output.Success {
		return fmt.Errorf("plugin %s post-resolve failed: %s", h.PluginName, output.Message)
	}
	return nil
}
