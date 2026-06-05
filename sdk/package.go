package sdk

import (
	"sort"
	"strings"
)

// PackageLocation captures where a package was discovered.
type PackageLocation struct {
	RealPath   string `json:"real_path,omitempty"`
	AccessPath string `json:"access_path,omitempty"`
	// Position optionally points at the exact line / column in RealPath where
	// the package is declared. nil when unknown.
	Position *SourcePosition `json:"position,omitempty"`
}

// PackageLicense captures normalized license details for a package.
type PackageLicense struct {
	Value          string `json:"value,omitempty"`
	SPDXExpression string `json:"spdx_expression,omitempty"`
	Type           string `json:"type,omitempty"`
}

// Digest captures integrity information for a package artifact.
type Digest struct {
	Algorithm string `json:"algorithm,omitempty"`
	Value     string `json:"value,omitempty"`
}

// PackageEOL captures end-of-life enrichment attached by the EOL matcher.
type PackageEOL struct {
	Source        string `json:"source,omitempty"`
	Cycle         string `json:"cycle,omitempty"`
	EOL           bool   `json:"eol,omitempty"`
	EOLDate       string `json:"eol_date,omitempty"`
	LatestVersion string `json:"latest_version,omitempty"`
	ReleaseDate   string `json:"release_date,omitempty"`
	Supported     bool   `json:"supported,omitempty"`
}

// Clone returns a deep copy of the EOL payload.
func (e *PackageEOL) Clone() *PackageEOL {
	if e == nil {
		return nil
	}
	return new(*e)
}

// Package describes one matching artifact: the PURL-keyed, deduplicated record
// produced by the matching stage. Many Dependency nodes (across manifests and
// subprojects) reference a single Package by PURL. A Package holds only
// matching-stage enrichment; detection-time identity and relationships live on
// Dependency.
type Package struct {
	// PURL is the canonical package URL and the registry primary key.
	PURL        string `json:"purl"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	Org         string `json:"org,omitempty"`
	Type        string `json:"type,omitempty"`
	BuildSystem string `json:"build_system,omitempty"`
	Language    string `json:"language,omitempty"`
	Copyright   string `json:"copyright,omitempty"`
	ResolvedURL string `json:"resolved_url,omitempty"`

	CPEs            []string          `json:"cpes,omitempty"`
	Digests         []Digest          `json:"digests,omitempty"`
	Licenses        []PackageLicense  `json:"licenses,omitempty"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities,omitempty"`
	Scorecard       *PackageScorecard `json:"scorecard,omitempty"`
	EOL             *PackageEOL       `json:"eol,omitempty"`

	// Matched indicates that this package was successfully matched by one or
	// more external enrichment sources.
	Matched bool `json:"matched,omitempty"`

	// Metadata holds per-ecosystem extensible data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// MetadataKeyNPM is the Metadata map key for *NPMPackageMetadata.
const MetadataKeyNPM = "npm"

// MetadataKeyDetectionLicenses is the Dependency.Metadata key under which
// detectors that discover license facts at detection time (e.g. SBOM-backed
// detectors) stash []PackageLicense for consolidation to lift into the
// package registry.
const MetadataKeyDetectionLicenses = "bomly.detection.licenses"

// NPMPackageMetadata holds npm-specific package data extracted from npm/pnpm/yarn
// lockfiles that does not fit into the cross-ecosystem fields.
type NPMPackageMetadata struct {
	Bundled                  bool              `json:"bundled,omitempty"`
	Extraneous               bool              `json:"extraneous,omitempty"`
	HasInstallScript         bool              `json:"hasInstallScript,omitempty"`
	PeerDependencies         map[string]string `json:"peerDependencies,omitempty"`
	OptionalPeerDependencies []string          `json:"optionalPeerDependencies,omitempty"`
	Engines                  map[string]string `json:"engines,omitempty"`
}

// QualifiedName returns the package name prefixed with its organization when present.
func (p *Package) QualifiedName() string {
	return qualifiedName(p.Org, p.Name)
}

// DisplayName returns the most human-friendly identifier available.
func (p *Package) DisplayName() string {
	if name := p.QualifiedName(); name != "" {
		return name
	}
	return p.PURL
}

// IdentityKey returns a stable package identity without version information.
func (p *Package) IdentityKey() string {
	if p == nil {
		return ""
	}
	return strings.Join([]string{p.Ecosystem, p.BuildSystem, p.Type, p.Org, p.Name}, "\x00")
}

// LicenseValues returns normalized package license labels in stable order.
func (p *Package) LicenseValues() []string {
	if p == nil || len(p.Licenses) == 0 {
		return nil
	}
	values := make([]string, 0, len(p.Licenses))
	for _, license := range p.Licenses {
		switch {
		case license.SPDXExpression != "":
			values = append(values, license.SPDXExpression)
		case license.Value != "":
			values = append(values, license.Value)
		}
	}
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	return values
}

// Clone returns a deep copy of the package.
func (p *Package) Clone() *Package {
	if p == nil {
		return nil
	}
	clone := *p
	clone.CPEs = cloneStrings(p.CPEs)
	if len(p.Digests) > 0 {
		clone.Digests = append([]Digest(nil), p.Digests...)
	}
	if len(p.Licenses) > 0 {
		clone.Licenses = append([]PackageLicense(nil), p.Licenses...)
	}
	if len(p.Vulnerabilities) > 0 {
		clone.Vulnerabilities = make([]Vulnerability, 0, len(p.Vulnerabilities))
		for _, v := range p.Vulnerabilities {
			clone.Vulnerabilities = append(clone.Vulnerabilities, v.Clone())
		}
	}
	clone.Scorecard = p.Scorecard.Clone()
	clone.EOL = p.EOL.Clone()
	clone.Metadata = cloneAnyMap(p.Metadata)
	return &clone
}

// MergeFrom folds enrichment from src into p in place. Used by the package
// registry to deduplicate multiple records for the same PURL. Existing typed
// data on p wins; src contributes anything p is missing, and vulnerability
// lists are unioned by (Source, ID).
func (p *Package) MergeFrom(src *Package) {
	if p == nil || src == nil {
		return
	}
	if p.Ecosystem == "" {
		p.Ecosystem = src.Ecosystem
	}
	if p.Name == "" {
		p.Name = src.Name
	}
	if p.Version == "" {
		p.Version = src.Version
	}
	if p.Org == "" {
		p.Org = src.Org
	}
	if p.Type == "" {
		p.Type = src.Type
	}
	if p.BuildSystem == "" {
		p.BuildSystem = src.BuildSystem
	}
	if p.Language == "" {
		p.Language = src.Language
	}
	if strings.TrimSpace(p.Copyright) == "" {
		p.Copyright = src.Copyright
	}
	if p.ResolvedURL == "" {
		p.ResolvedURL = src.ResolvedURL
	}
	if len(p.CPEs) == 0 {
		p.CPEs = cloneStrings(src.CPEs)
	}
	if len(p.Digests) == 0 && len(src.Digests) > 0 {
		p.Digests = append([]Digest(nil), src.Digests...)
	}
	if len(p.Licenses) == 0 && len(src.Licenses) > 0 {
		p.Licenses = append([]PackageLicense(nil), src.Licenses...)
	}
	if p.Scorecard == nil {
		p.Scorecard = src.Scorecard.Clone()
	}
	if p.EOL == nil {
		p.EOL = src.EOL.Clone()
	}
	if src.Matched {
		p.Matched = true
	}
	p.mergeVulnerabilities(src.Vulnerabilities)
	if len(src.Metadata) > 0 {
		if p.Metadata == nil {
			p.Metadata = make(map[string]any, len(src.Metadata))
		}
		for k, v := range src.Metadata {
			if _, exists := p.Metadata[k]; !exists {
				p.Metadata[k] = v
			}
		}
	}
}

func (p *Package) mergeVulnerabilities(incoming []Vulnerability) {
	if len(incoming) == 0 {
		return
	}
	idx := make(map[string]int, len(p.Vulnerabilities))
	for i, v := range p.Vulnerabilities {
		idx[v.Source+"\x00"+v.ID] = i
	}
	for _, v := range incoming {
		key := v.Source + "\x00" + v.ID
		if existing, ok := idx[key]; ok {
			dst := &p.Vulnerabilities[existing]
			if dst.Reachability == nil && v.Reachability != nil {
				dst.Reachability = v.Reachability.Clone()
			}
			if len(dst.AffectedSymbols) == 0 && len(v.AffectedSymbols) > 0 {
				dst.AffectedSymbols = make([]AffectedSymbol, 0, len(v.AffectedSymbols))
				for _, sym := range v.AffectedSymbols {
					dst.AffectedSymbols = append(dst.AffectedSymbols, sym.Clone())
				}
			}
			continue
		}
		p.Vulnerabilities = append(p.Vulnerabilities, v.Clone())
		idx[key] = len(p.Vulnerabilities) - 1
	}
}

// SetDetectionLicenses stashes detection-time license facts on dep's metadata
// under MetadataKeyDetectionLicenses, so consolidation can lift them into the
// package registry. No-op when dep is nil or licenses is empty.
func SetDetectionLicenses(dep *Dependency, licenses []PackageLicense) {
	if dep == nil || len(licenses) == 0 {
		return
	}
	if dep.Metadata == nil {
		dep.Metadata = make(map[string]any, 1)
	}
	dep.Metadata[MetadataKeyDetectionLicenses] = licenses
}

// DetectionLicenses returns license facts stashed on dep at detection time.
func DetectionLicenses(dep *Dependency) []PackageLicense {
	if dep == nil || dep.Metadata == nil {
		return nil
	}
	if v, ok := dep.Metadata[MetadataKeyDetectionLicenses].([]PackageLicense); ok {
		return v
	}
	return nil
}

// PackageFromDependency seeds a registry package from a dependency's identity
// fields. The returned package carries no enrichment; matchers fill it in.
func PackageFromDependency(dep *Dependency) *Package {
	if dep == nil {
		return nil
	}
	purl := CanonicalPackageURLFromDependency(dep)
	return &Package{
		PURL:        purl,
		Ecosystem:   dep.Ecosystem,
		Name:        dep.Name,
		Version:     dep.Version,
		Org:         dep.Org,
		Type:        dep.Type,
		BuildSystem: dep.BuildSystem,
		Language:    dep.Language,
		ResolvedURL: dep.ResolvedURL,
	}
}

func qualifiedName(org, name string) string {
	if org == "" {
		return name
	}
	if name == "" {
		return org
	}
	return org + ":" + name
}
