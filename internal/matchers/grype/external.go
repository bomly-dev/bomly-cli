//go:build bomly_external_grype

package grype

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/matchers"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// Ready reports whether the external grype binary is available.
func (a Matcher) Ready() bool {
	_, err := exec.LookPath("grype")
	return err == nil
}

// Match attaches Grype vulnerability matches by shelling out to the grype CLI binary.
func (a Matcher) Match(_ context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	started := time.Now()
	if req.Graph == nil {
		return sdk.MatchResult{}, nil
	}

	logger := a.logger()

	if req.Graph == nil || req.Registry == nil {
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{matcherName}}, nil
	}

	// Seed the registry so SPDX serialization and match correlation share PURLs.
	_ = matchers.RegistryPackagesForGraph(req.Graph, req.Registry, req.Target)

	// Serialize graph as SPDX JSON to feed to grype stdin.
	spdxBytes, err := sbom.MarshalDepGraphJSON(req.Graph, sbom.TargetSPDX23JSON, sbom.BuildOptions{}, sbom.EncodeOptions{})
	if err != nil {
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{matcherName}}, fmt.Errorf("grype: serialize sbom: %w", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := system.Command("grype", "-o", "json")
	cmd.Stdin = bytes.NewReader(spdxBytes)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Debug("running external grype matcher")
	if err := cmd.Run(); err != nil {
		logger.Warn(fmt.Sprintf("grype CLI failed: %v (stderr: %s)", err, stderr.String()))
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{matcherName}}, fmt.Errorf("grype match failed: %w", err)
	}

	err = parseGrypeJSONOutput(stdout.Bytes(), req.Registry)
	if err != nil {
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{matcherName}}, fmt.Errorf("grype: parse output: %w", err)
	}

	logger.Info(fmt.Sprintf("External grype enrichment completed in %s", logging.FormatDuration(time.Since(started))))
	return sdk.MatchResult{
		Registry:    req.Registry,
		MatcherRuns: []string{matcherName},
	}, nil
}

// grypeJSONOutput represents the top-level structure of grype JSON output.
type grypeJSONOutput struct {
	Matches []grypeJSONMatch `json:"matches"`
}

type grypeJSONMatch struct {
	Vulnerability          grypeJSONVuln       `json:"vulnerability"`
	RelatedVulnerabilities []grypeJSONVulnMeta `json:"relatedVulnerabilities"`
	MatchDetails           []grypeJSONDetail   `json:"matchDetails"`
	Artifact               grypeJSONArtifact   `json:"artifact"`
}

type grypeJSONVuln struct {
	grypeJSONVulnMeta
	Fix        grypeJSONFix        `json:"fix"`
	Advisories []grypeJSONAdvisory `json:"advisories"`
	Risk       float64             `json:"risk"`
}

type grypeJSONVulnMeta struct {
	ID             string                  `json:"id"`
	DataSource     string                  `json:"dataSource"`
	Namespace      string                  `json:"namespace"`
	Severity       string                  `json:"severity"`
	URLs           []string                `json:"urls"`
	Description    string                  `json:"description"`
	CVSS           []grypeJSONCVSS         `json:"cvss"`
	KnownExploited []grypeJSONKnownExploit `json:"knownExploited"`
	EPSS           []grypeJSONEPSS         `json:"epss"`
	CWEs           []grypeJSONCWE          `json:"cwes"`
}

type grypeJSONFix struct {
	Versions  []string                `json:"versions"`
	State     string                  `json:"state"`
	Available []grypeJSONFixAvailable `json:"available"`
}

type grypeJSONFixAvailable struct {
	Version string `json:"version"`
	Date    string `json:"date"`
	Kind    string `json:"kind"`
}

type grypeJSONAdvisory struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}

type grypeJSONCVSS struct {
	Source  string              `json:"source"`
	Type    string              `json:"type"`
	Version string              `json:"version"`
	Vector  string              `json:"vector"`
	Metrics grypeJSONCVSSMetric `json:"metrics"`
}

type grypeJSONCVSSMetric struct {
	BaseScore float64 `json:"baseScore"`
}

type grypeJSONKnownExploit struct {
	CVE                        string   `json:"cve"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	DateAdded                  string   `json:"dateAdded"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	URLs                       []string `json:"urls"`
	CWEs                       []string `json:"cwes"`
}

type grypeJSONEPSS struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

type grypeJSONCWE struct {
	CVE    string `json:"cve"`
	CWE    string `json:"cwe"`
	Source string `json:"source"`
	Type   string `json:"type"`
}

type grypeJSONDetail struct {
	Found json.RawMessage      `json:"found"`
	Fix   *grypeJSONFixDetails `json:"fix"`
}

type grypeJSONFixDetails struct {
	SuggestedVersion string `json:"suggestedVersion"`
}

type grypeJSONArtifact struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	CPEs    []string `json:"cpes"`
	PURL    string   `json:"purl"`
}

func parseGrypeJSONOutput(data []byte, registry *sdk.PackageRegistry) error {
	var out grypeJSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("decode grype json: %w", err)
	}
	if registry == nil {
		return nil
	}

	for _, m := range out.Matches {
		purl := strings.TrimSpace(m.Artifact.PURL)
		if purl == "" {
			continue
		}
		pkg := registry.Ensure(purl)
		if pkg == nil {
			continue
		}
		pkg.Matched = true
		pkg.Vulnerabilities = appendOrMergeVulnerability(pkg.Vulnerabilities, mapGrypeJSONMatch(m))
	}
	return nil
}

func mapGrypeJSONMatch(m grypeJSONMatch) sdk.Vulnerability {
	advisory := grypeAdvisory{
		ID:                   m.Vulnerability.ID,
		Namespace:            m.Vulnerability.Namespace,
		DataSource:           m.Vulnerability.DataSource,
		Severity:             m.Vulnerability.Severity,
		SeveritySource:       m.Vulnerability.Namespace,
		Description:          m.Vulnerability.Description,
		URLs:                 append([]string(nil), m.Vulnerability.URLs...),
		CVSS:                 jsonCVSS(m.Vulnerability.CVSS),
		FixedVersions:        append([]string(nil), m.Vulnerability.Fix.Versions...),
		FixedIn:              suggestedFixedVersion(m.MatchDetails),
		FixState:             m.Vulnerability.Fix.State,
		FixAvailable:         jsonFixAvailable(m.Vulnerability.Fix.Available),
		AffectedVersionRange: foundConstraint(m.MatchDetails),
		References:           jsonReferences(m.Vulnerability.Advisories),
		Aliases:              jsonAliases(m.RelatedVulnerabilities),
		KnownExploited:       jsonKnownExploited(m.Vulnerability.KnownExploited),
		EPSS:                 jsonEPSS(m.Vulnerability.EPSS),
		CWEs:                 jsonCWEs(m.Vulnerability.CWEs),
		RiskScore:            m.Vulnerability.Risk,
		CPEs:                 append([]string(nil), m.Artifact.CPEs...),
	}
	return mapGrypeAdvisory(advisory)
}

func suggestedFixedVersion(details []grypeJSONDetail) string {
	for _, detail := range details {
		if detail.Fix != nil && detail.Fix.SuggestedVersion != "" {
			return detail.Fix.SuggestedVersion
		}
	}
	return ""
}

func foundConstraint(details []grypeJSONDetail) string {
	for _, detail := range details {
		var found struct {
			Constraint string `json:"constraint"`
		}
		if len(detail.Found) == 0 || json.Unmarshal(detail.Found, &found) != nil {
			continue
		}
		if found.Constraint != "" {
			return found.Constraint
		}
	}
	return ""
}

func jsonCVSS(values []grypeJSONCVSS) []sdk.CVSSScore {
	out := make([]sdk.CVSSScore, 0, len(values))
	for _, value := range values {
		out = append(out, sdk.CVSSScore{
			Vector:  value.Vector,
			Score:   value.Metrics.BaseScore,
			Version: value.Version,
			Source:  value.Source,
		})
	}
	return out
}

func jsonFixAvailable(values []grypeJSONFixAvailable) []sdk.FixAvailable {
	out := make([]sdk.FixAvailable, 0, len(values))
	for _, value := range values {
		out = append(out, sdk.FixAvailable{Version: value.Version, Date: value.Date, Kind: value.Kind})
	}
	return out
}

func jsonReferences(values []grypeJSONAdvisory) []sdk.Reference {
	out := make([]sdk.Reference, 0, len(values))
	for _, value := range values {
		out = append(out, sdk.Reference{URL: value.Link, Type: firstNonEmpty(value.ID, "advisory")})
	}
	return out
}

func jsonAliases(values []grypeJSONVulnMeta) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.ID)
	}
	return out
}

func jsonKnownExploited(values []grypeJSONKnownExploit) []sdk.KnownExploited {
	out := make([]sdk.KnownExploited, 0, len(values))
	for _, value := range values {
		out = append(out, sdk.KnownExploited{
			CVE:                        value.CVE,
			VendorProject:              value.VendorProject,
			Product:                    value.Product,
			DateAdded:                  value.DateAdded,
			RequiredAction:             value.RequiredAction,
			DueDate:                    value.DueDate,
			KnownRansomwareCampaignUse: value.KnownRansomwareCampaignUse,
			Notes:                      value.Notes,
			URLs:                       append([]string(nil), value.URLs...),
			CWEs:                       append([]string(nil), value.CWEs...),
		})
	}
	return out
}

func jsonEPSS(values []grypeJSONEPSS) []sdk.EPSSScore {
	out := make([]sdk.EPSSScore, 0, len(values))
	for _, value := range values {
		out = append(out, sdk.EPSSScore{CVE: value.CVE, EPSS: value.EPSS, Percentile: value.Percentile, Date: value.Date})
	}
	return out
}

func jsonCWEs(values []grypeJSONCWE) []sdk.CWE {
	out := make([]sdk.CWE, 0, len(values))
	for _, value := range values {
		out = append(out, sdk.CWE{CVE: value.CVE, ID: value.CWE, Source: value.Source, Type: value.Type})
	}
	return out
}
