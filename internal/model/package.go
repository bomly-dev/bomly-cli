package model

import (
	"fmt"
	"sort"
	"strings"
)

// PackageLocation captures where a package was discovered.
type PackageLocation struct {
	RealPath   string
	AccessPath string
}

// PackageLicense captures normalized license details for a package.
type PackageLicense struct {
	Value          string
	SPDXExpression string
	Type           string
}

// Digest captures integrity information for a package artifact.
type Digest struct {
	Algorithm string
	Value     string
}

// Package describes one node in the directed dependency graph.
type Package struct {
	ID          string
	Ecosystem   string
	Name        string
	Version     string
	Scope       string
	Org         string
	BuildSystem string
	Type        string
	Language    string
	PURL        string
	Copyright   string
	FoundBy     string
	Licenses    []PackageLicense
	Locations   []PackageLocation
	CPEs        []string
	Digests     []Digest

	// Matched indicates that this package was successfully matched by one or
	// more external enrichment sources (e.g. deps.dev, ClearlyDefined).
	Matched bool

	// Vulnerabilities stores first-class package vulnerability enrichment
	// attached by matchers such as OSV and Grype.
	Vulnerabilities []PackageVulnerability

	// Metadata holds per-ecosystem extensible data.
	Metadata map[string]any
}

// QualifiedName returns the package name prefixed with its organization when present.
func (p Package) QualifiedName() string {
	if p.Org == "" {
		return p.Name
	}
	if p.Name == "" {
		return p.Org
	}
	return p.Org + ":" + p.Name
}

// DisplayName returns the most human-friendly identifier available for the package.
func (p Package) DisplayName() string {
	if name := p.QualifiedName(); name != "" {
		return name
	}
	return p.ID
}

// StableID returns the stable graph identifier for the package.
func (p Package) StableID() string {
	base := p.QualifiedName()
	if p.Version == "" {
		return base
	}
	if base == "" {
		return p.Version
	}
	return fmt.Sprintf("%s@%s", base, p.Version)
}

// Clone returns a deep copy of the package.
func (p *Package) Clone() *Package {
	if p == nil {
		return nil
	}
	clone := *p
	if len(p.Licenses) > 0 {
		clone.Licenses = append([]PackageLicense(nil), p.Licenses...)
	}
	if len(p.Locations) > 0 {
		clone.Locations = append([]PackageLocation(nil), p.Locations...)
	}
	if len(p.CPEs) > 0 {
		clone.CPEs = append([]string(nil), p.CPEs...)
	}
	if len(p.Digests) > 0 {
		clone.Digests = append([]Digest(nil), p.Digests...)
	}
	if len(p.Vulnerabilities) > 0 {
		clone.Vulnerabilities = make([]PackageVulnerability, 0, len(p.Vulnerabilities))
		for _, vulnerability := range p.Vulnerabilities {
			clone.Vulnerabilities = append(clone.Vulnerabilities, vulnerability.Clone())
		}
	}
	if len(p.Metadata) > 0 {
		clone.Metadata = make(map[string]any, len(p.Metadata))
		for k, v := range p.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

// WithoutID returns the package data without the precomputed graph ID.
func (p *Package) WithoutID() Package {
	if p == nil {
		return Package{}
	}
	clone := p.Clone()
	clone.ID = ""
	return *clone
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

// NewPackage constructs a dependency package from its fields.
func NewPackage(pkg Package) *Package {
	return NewPackageWithID(pkg.StableID(), pkg)
}

// NewPackageWithID constructs a dependency package with a custom ID.
func NewPackageWithID(id string, pkg Package) *Package {
	clone := pkg.Clone()
	clone.ID = id
	return clone
}

// NewPackageRef constructs a dependency package.
// If version is set, ID is "name@version"; otherwise ID is "name".
func NewPackageRef(name, version string) *Package {
	return NewPackage(Package{Name: name, Version: version})
}

// NewPackageRefWithID constructs a dependency package with a custom ID.
func NewPackageRefWithID(id, name, version string) *Package {
	return NewPackageWithID(id, Package{Name: name, Version: version})
}
