//go:build !bomly_external_grype

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
	grypevuln "github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/matchers"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// clioID is the clio application identity presented when opening the Grype vulnerability DB.
var clioID = grypeclio.Identification{Name: "grype"}

// Ready reports whether the bundled Grype matcher can run. The database may be
// downloaded during Match on first use, so a missing cache does not make the
// matcher unavailable.
func (a Matcher) Ready() bool {
	return true
}

// Match attaches Grype vulnerability matches to packages in the graph.
func (a Matcher) Match(_ context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	started := time.Now()
	if req.Graph == nil || req.Registry == nil {
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{matcherName}, MatcherRunDetails: grypeMatcherRuns(0, 0)}, nil
	}

	logger := a.logger()

	needsDownload := !a.dbExists()
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
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{matcherName}, MatcherRunDetails: grypeMatcherRuns(0, 0)}, fmt.Errorf("grype vulnerability DB %s failed: %w", action, err)
	}
	if status != nil {
		logger.Debug(fmt.Sprintf("Grype vulnerability DB loaded, built at %s", status.Built))
	}

	packages := matchers.RegistryPackagesForGraph(req.Graph, req.Registry, req.Target)
	logger.Info(fmt.Sprintf("Grype enriching %d packages with vulnerability data", len(packages)))
	grypePkgs := make([]grypepkg.Package, 0, len(packages))
	for _, p := range packages {
		if p.Name == "" {
			continue
		}
		grypePkgs = append(grypePkgs, graphPkgToGrypePkg(p))
	}

	matcher := grypematcher.NewDefaultMatchers(grypematcher.Config{})
	vm := &grypelib.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              matcher,
	}

	matches, _, err := vm.FindMatches(grypePkgs, grypepkg.Context{})
	if err != nil {
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{matcherName}, MatcherRunDetails: grypeMatcherRuns(0, 0)}, fmt.Errorf("grype: find matches: %w", err)
	}

	applyMatches(matches, req.Registry)
	matchedPackages, vulnerabilities := grypeMatchCounts(matches)
	logger.Info(fmt.Sprintf("Grype enrichment matched vulnerabilities in %s", logging.FormatDuration(time.Since(started))))
	return sdk.MatchResult{
		Registry:          req.Registry,
		MatcherRuns:       []string{matcherName},
		MatcherRunDetails: grypeMatcherRuns(matchedPackages, vulnerabilities),
	}, nil
}

// graphPkgToGrypePkg builds a Grype package from a registry package, using the
// canonical PURL as the correlation ID so matches can be mapped back to the
// registry.
func graphPkgToGrypePkg(p *sdk.Package) grypepkg.Package {
	return grypepkg.Package{
		ID:       grypepkg.ID(p.PURL),
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
	case "maven", "java", "gradle", "scala", "sbt":
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
	case "maven", "java", "gradle", "scala", "sbt":
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

// applyMatches converts Grype match results into vulnerability enrichment on the
// PURL-keyed package registry. The Grype package ID was set to the canonical
// PURL by graphPkgToGrypePkg.
func applyMatches(matches *grypematch.Matches, registry *sdk.PackageRegistry) {
	if matches == nil || registry == nil {
		return
	}

	for _, m := range matches.Sorted() {
		purl := string(m.Package.ID)
		if purl == "" {
			purl = m.Package.PURL
		}
		if purl == "" {
			continue
		}
		pkg := registry.Ensure(purl)
		if pkg == nil {
			continue
		}
		pkg.Matched = true
		pkg.Vulnerabilities = appendOrMergeVulnerability(pkg.Vulnerabilities, mapBuiltinMatch(m))
	}
}

func grypeMatchCounts(matches *grypematch.Matches) (int, int) {
	if matches == nil {
		return 0, 0
	}
	seen := make(map[string]struct{})
	vulnerabilities := 0
	for _, m := range matches.Sorted() {
		purl := string(m.Package.ID)
		if purl == "" {
			purl = m.Package.PURL
		}
		if purl != "" {
			seen[purl] = struct{}{}
		}
		vulnerabilities++
	}
	return len(seen), vulnerabilities
}

func mapBuiltinMatch(m grypematch.Match) sdk.Vulnerability {
	vuln := m.Vulnerability
	advisory := grypeAdvisory{
		ID:                   vuln.ID,
		Namespace:            vuln.Namespace,
		FixedVersions:        append([]string(nil), vuln.Fix.Versions...),
		FixState:             string(vuln.Fix.State),
		AffectedVersionRange: constraintString(vuln.Constraint),
		CPEs:                 cpeStrings(vuln.CPEs),
	}
	if vuln.Metadata != nil {
		advisory.DataSource = vuln.Metadata.DataSource
		advisory.Namespace = firstNonEmpty(vuln.Metadata.Namespace, advisory.Namespace)
		advisory.Severity = vuln.Metadata.Severity
		advisory.SeveritySource = vuln.Metadata.Namespace
		advisory.Description = vuln.Metadata.Description
		advisory.URLs = append([]string(nil), vuln.Metadata.URLs...)
		advisory.CVSS = builtinCVSS(vuln.Metadata.Cvss)
		advisory.KnownExploited = builtinKnownExploited(vuln.Metadata.KnownExploited)
		advisory.EPSS = builtinEPSS(vuln.Metadata.EPSS)
		advisory.CWEs = builtinCWEs(vuln.Metadata.CWEs)
		advisory.RiskScore = vuln.Metadata.RiskScore()
	}
	for _, fix := range vuln.Fix.Available {
		advisory.FixAvailable = append(advisory.FixAvailable, sdk.FixAvailable{
			Version: fix.Version,
			Date:    dateString(fix.Date),
			Kind:    fix.Kind,
		})
	}
	for _, advisoryRef := range vuln.Advisories {
		advisory.References = append(advisory.References, sdk.Reference{URL: advisoryRef.Link, Type: firstNonEmpty(advisoryRef.ID, "advisory")})
	}
	for _, related := range vuln.RelatedVulnerabilities {
		if related.ID != "" {
			advisory.Aliases = append(advisory.Aliases, related.ID)
		}
	}
	return mapGrypeAdvisory(advisory)
}

func constraintString(constraint fmt.Stringer) string {
	if constraint == nil {
		return ""
	}
	return constraint.String()
}

func builtinCVSS(scores []grypevuln.Cvss) []sdk.CVSSScore {
	if len(scores) == 0 {
		return nil
	}
	out := make([]sdk.CVSSScore, 0, len(scores))
	for _, score := range scores {
		if score.Vector == "" && score.Metrics.BaseScore == 0 {
			continue
		}
		out = append(out, sdk.CVSSScore{
			Vector:  score.Vector,
			Score:   score.Metrics.BaseScore,
			Version: score.Version,
			Source:  score.Source,
		})
	}
	return out
}

func builtinKnownExploited(values []grypevuln.KnownExploited) []sdk.KnownExploited {
	if len(values) == 0 {
		return nil
	}
	out := make([]sdk.KnownExploited, 0, len(values))
	for _, value := range values {
		out = append(out, sdk.KnownExploited{
			CVE:                        value.CVE,
			VendorProject:              value.VendorProject,
			Product:                    value.Product,
			DateAdded:                  datePtrString(value.DateAdded),
			RequiredAction:             value.RequiredAction,
			DueDate:                    datePtrString(value.DueDate),
			KnownRansomwareCampaignUse: value.KnownRansomwareCampaignUse,
			Notes:                      value.Notes,
			URLs:                       append([]string(nil), value.URLs...),
			CWEs:                       append([]string(nil), value.CWEs...),
		})
	}
	return out
}

func builtinEPSS(values []grypevuln.EPSS) []sdk.EPSSScore {
	if len(values) == 0 {
		return nil
	}
	out := make([]sdk.EPSSScore, 0, len(values))
	for _, value := range values {
		out = append(out, sdk.EPSSScore{
			CVE:        value.CVE,
			EPSS:       value.EPSS,
			Percentile: value.Percentile,
			Date:       dateString(value.Date),
		})
	}
	return out
}

func builtinCWEs(values []grypevuln.CWE) []sdk.CWE {
	if len(values) == 0 {
		return nil
	}
	out := make([]sdk.CWE, 0, len(values))
	for _, value := range values {
		out = append(out, sdk.CWE{
			CVE:    value.CVE,
			ID:     value.CWE,
			Source: value.Source,
			Type:   value.Type,
		})
	}
	return out
}

func cpeStrings(values []cpe.CPE) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.Attributes.String())
	}
	return out
}

func dateString(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.DateOnly)
}

func datePtrString(value *time.Time) string {
	if value == nil {
		return ""
	}
	return dateString(*value)
}
