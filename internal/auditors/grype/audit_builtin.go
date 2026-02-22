//go:build bomly_builtin_grype

package grype

import (
	"context"
	"fmt"
	"strings"
	"time"

	grypeclio "github.com/anchore/clio"
	grypelib "github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	grypematch "github.com/anchore/grype/grype/match"
	grypematcher "github.com/anchore/grype/grype/matcher"
	grypepkg "github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"

	"github.com/bomly/bomly-cli/internal/logging"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/scan"
	"go.uber.org/zap"
)

// clioID is the clio application identity presented when opening the Grype vulnerability DB.
var clioID = grypeclio.Identification{Name: "grype"}

// Audit matches every package in the graph against the local Grype vulnerability database.
func (a Auditor) Audit(_ context.Context, req scan.AuditRequest) (scan.AuditResult, error) {
	started := time.Now()
	if req.Graph == nil {
		return scan.AuditResult{}, nil
	}

	logger := a.logger()

	needsDownload := !a.Ready()
	if needsDownload {
		logger.Info(fmt.Sprintf("Grype vulnerability DB not found; downloading now at %s", a.dbDir()))
	}

	distCfg := v6dist.DefaultConfig()
	if dc, ok := a.DistConfigOverride.(*v6dist.Config); ok && dc != nil {
		distCfg = *dc
	}
	distCfg.ID = clioID
	installCfg := v6inst.DefaultConfig(clioID)
	installCfg.DBRootDir = a.dbDir()
	installCfg.ValidateAge = false

	logger.Debug(fmt.Sprintf("Grype loading vulnerability database from %s", a.dbDir()))
	provider, status, err := grypelib.LoadVulnerabilityDB(distCfg, installCfg, needsDownload)
	if err != nil {
		logger.Warn("Grype failed to load vulnerability DB, skipping", zap.Error(err))
		action := "loading"
		if needsDownload {
			action = "downloading"
		}
		return scan.AuditResult{Graph: req.Graph, Target: req.Target}, fmt.Errorf("grype vulnerability DB %s failed: %w", action, err)
	}
	if status != nil {
		logger.Debug(fmt.Sprintf("Grype vulnerability DB loaded, built at %s", status.Built))
	}

	packages := req.Graph.Packages()
	if req.Mode == scan.TargetModeComponent && req.Target != nil {
		packages = []*model.Package{req.Target}
	}
	logger.Info(fmt.Sprintf("Grype auditing %d packages for vulnerabilities", len(packages)))
	grypePkgs := make([]grypepkg.Package, 0, len(packages))
	for _, p := range packages {
		if p.Name == "" {
			continue
		}
		grypePkgs = append(grypePkgs, graphPkgToGrypePkg(p))
	}

	matchers := grypematcher.NewDefaultMatchers(grypematcher.Config{})
	vm := &grypelib.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              matchers,
	}

	matches, _, err := vm.FindMatches(grypePkgs, grypepkg.Context{})
	if err != nil {
		return scan.AuditResult{}, fmt.Errorf("grype: find matches: %w", err)
	}

	findings := convertMatches(matches, req.Graph)
	logger.Info(fmt.Sprintf("Grype audit found %d findings in %s", len(findings), logging.FormatDuration(time.Since(started))))
	return scan.AuditResult{
		Graph:    req.Graph,
		Target:   req.Target,
		Findings: findings,
	}, nil
}

func graphPkgToGrypePkg(p *model.Package) grypepkg.Package {
	return grypepkg.Package{
		ID:       grypepkg.ID(p.ID),
		Name:     p.Name,
		Version:  p.Version,
		PURL:     p.PURL,
		Type:     ecosystemToSyftType(p.Ecosystem),
		Language: ecosystemToSyftLanguage(p.Ecosystem),
	}
}

func ecosystemToSyftType(ecosystem string) syftPkg.Type {
	switch strings.ToLower(ecosystem) {
	case "npm", "nodejs":
		return syftPkg.NpmPkg
	case "maven", "java", "gradle":
		return syftPkg.JavaPkg
	case "go", "golang":
		return syftPkg.GoModulePkg
	case "python", "pypi":
		return syftPkg.PythonPkg
	case "dotnet", "nuget":
		return syftPkg.DotnetPkg
	case "ruby", "rubygems":
		return syftPkg.GemPkg
	case "rust", "cargo":
		return syftPkg.RustPkg
	case "rpm":
		return syftPkg.RpmPkg
	case "apk":
		return syftPkg.ApkPkg
	case "dpkg", "deb":
		return syftPkg.DebPkg
	case "dart":
		return syftPkg.DartPubPkg
	case "elixir", "erlang", "hex":
		return syftPkg.HexPkg
	case "php":
		return syftPkg.PhpComposerPkg
	case "swift":
		return syftPkg.SwiftPkg
	case "haskell":
		return syftPkg.HackagePkg
	case "r":
		return syftPkg.Rpkg
	case "lua":
		return syftPkg.LuaRocksPkg
	default:
		return syftPkg.UnknownPkg
	}
}

func ecosystemToSyftLanguage(ecosystem string) syftPkg.Language {
	switch strings.ToLower(ecosystem) {
	case "npm", "nodejs":
		return syftPkg.JavaScript
	case "maven", "java", "gradle":
		return syftPkg.Java
	case "go", "golang":
		return syftPkg.Go
	case "python", "pypi":
		return syftPkg.Python
	case "dotnet", "nuget":
		return syftPkg.Dotnet
	case "ruby", "rubygems":
		return syftPkg.Ruby
	case "rust", "cargo":
		return syftPkg.Rust
	case "dart":
		return syftPkg.Dart
	case "elixir", "erlang", "hex":
		return syftPkg.Elixir
	case "php":
		return syftPkg.PHP
	case "swift":
		return syftPkg.Swift
	case "haskell":
		return syftPkg.Haskell
	case "r":
		return syftPkg.R
	case "lua":
		return syftPkg.Lua
	default:
		return syftPkg.UnknownLanguage
	}
}

// convertMatches converts Grype match results to bomly scan.Findings.
func convertMatches(matches *grypematch.Matches, g *model.Graph) []scan.Finding {
	if matches == nil {
		return nil
	}

	pkgByID := make(map[grypepkg.ID]*model.Package)
	for _, p := range g.Packages() {
		pkgByID[grypepkg.ID(p.ID)] = p
	}

	var findings []scan.Finding
	for _, m := range matches.Sorted() {
		vuln := m.Vulnerability
		severity := "unknown"
		description := ""
		var urls []string
		if vuln.Metadata != nil {
			if vuln.Metadata.Severity != "" {
				severity = strings.ToLower(vuln.Metadata.Severity)
			}
			description = vuln.Metadata.Description
			urls = vuln.Metadata.URLs
		}

		graphPkg := pkgByID[m.Package.ID]
		if graphPkg == nil {
			graphPkg = &model.Package{
				ID:      string(m.Package.ID),
				Name:    m.Package.Name,
				Version: m.Package.Version,
				PURL:    m.Package.PURL,
			}
		}

		title := vuln.ID
		if description != "" {
			title = description
		}

		findings = append(findings, scan.Finding{
			ID:       vuln.ID,
			Kind:     scan.FindingKindVulnerability,
			Package:  graphPkg,
			Title:    title,
			Severity: severity,
			Reasons:  urls,
			Source:   auditorName,
		})
	}
	return findings
}
