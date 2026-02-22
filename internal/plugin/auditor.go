package plugin

import (
	"context"
	"fmt"

	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/scan"
)

// Auditor adapts a plugin with an audit stage to scan.Auditor.
type Auditor struct {
	PluginPath  string
	PluginName  string
	Subcommand  string
	CoreVersion string
	RunOpts     RunOptions
}

// Descriptor returns the auditor metadata.
func (a Auditor) Descriptor() scan.AuditorDescriptor {
	return scan.AuditorDescriptor{
		Name: a.PluginName + "-plugin-auditor",
	}
}

// Audit runs the plugin audit stage via the JSON envelope protocol.
func (a Auditor) Audit(_ context.Context, req scan.AuditRequest) (scan.AuditResult, error) {
	packages := packagesFromGraph(req.Graph)

	input := AuditInput{
		Packages: packages,
	}

	env, err := RunWithEnvelope(a.PluginPath, a.Subcommand, StageAudit, input, req.Stderr, a.CoreVersion, a.RunOpts)
	if err != nil {
		return scan.AuditResult{}, fmt.Errorf("plugin %s audit: %w", a.PluginName, err)
	}

	output, err := DecodePayload[AuditOutput](env)
	if err != nil {
		return scan.AuditResult{}, fmt.Errorf("plugin %s audit: %w", a.PluginName, err)
	}

	findings := make([]scan.Finding, 0, len(output.Findings))
	for _, f := range output.Findings {
		findings = append(findings, scan.Finding{
			ID:       f.ID,
			Source:   f.Source,
			Severity: f.Severity,
			Title:    f.Summary,
		})
	}

	return scan.AuditResult{Findings: findings}, nil
}

func packagesFromGraph(g *model.Graph) []PackageInfo {
	if g == nil {
		return nil
	}
	packages := g.Packages()
	out := make([]PackageInfo, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, PackageInfo{
			Name:    pkg.Name,
			Version: pkg.Version,
			PURL:    pkg.PURL,
		})
	}
	return out
}
