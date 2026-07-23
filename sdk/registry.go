package sdk

import "sort"

// PackageRegistry is the PURL-keyed, deduplicated set of matching artifacts
// produced by the matching stage. Detection produces Dependency nodes that
// reference packages here by PURL; matchers enrich the packages once per PURL
// regardless of how many dependency instances point at them.
type PackageRegistry struct {
	byPURL map[string]*Package
	order  []string
}

// NewPackageRegistry creates an empty registry.
func NewPackageRegistry() *PackageRegistry {
	return &PackageRegistry{byPURL: make(map[string]*Package)}
}

// Add inserts pkg, merging into any existing record with the same PURL, and
// returns the canonical stored package. Packages without a PURL are ignored.
func (r *PackageRegistry) Add(pkg *Package) *Package {
	if r == nil || pkg == nil || pkg.PURL == "" {
		return nil
	}
	if r.byPURL == nil {
		r.byPURL = make(map[string]*Package)
	}
	if pkg.ID == "" {
		pkg.ID = pkg.PURL
	}
	if existing, ok := r.byPURL[pkg.PURL]; ok {
		existing.MergeFrom(pkg)
		return existing
	}
	stored := pkg.Clone()
	r.byPURL[pkg.PURL] = stored
	r.order = append(r.order, pkg.PURL)
	return stored
}

// Ensure returns the registry package for purl, creating an empty one when
// absent. Returns nil for an empty purl.
func (r *PackageRegistry) Ensure(purl string) *Package {
	if r == nil || purl == "" {
		return nil
	}
	if r.byPURL == nil {
		r.byPURL = make(map[string]*Package)
	}
	if existing, ok := r.byPURL[purl]; ok {
		return existing
	}
	stored := &Package{Coordinates: Coordinates{PURL: purl}, ID: purl}
	r.byPURL[purl] = stored
	r.order = append(r.order, purl)
	return stored
}

// Get returns the package for purl, if present.
func (r *PackageRegistry) Get(purl string) (*Package, bool) {
	if r == nil || r.byPURL == nil {
		return nil, false
	}
	pkg, ok := r.byPURL[purl]
	return pkg, ok
}

// All returns every package sorted by PURL.
func (r *PackageRegistry) All() []*Package {
	if r == nil || len(r.byPURL) == 0 {
		return nil
	}
	purls := make([]string, 0, len(r.byPURL))
	for purl := range r.byPURL {
		purls = append(purls, purl)
	}
	sort.Strings(purls)
	out := make([]*Package, 0, len(purls))
	for _, purl := range purls {
		out = append(out, r.byPURL[purl])
	}
	return out
}

// Len returns the number of packages in the registry.
func (r *PackageRegistry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.byPURL)
}

// ConsolidateVulnerabilities merges alias-equivalent vulnerability records
// within each package and returns the record counts before and after.
func (r *PackageRegistry) ConsolidateVulnerabilities() (before, after int) {
	if r == nil {
		return 0, 0
	}
	for _, pkg := range r.All() {
		before += len(pkg.Vulnerabilities)
		pkg.Vulnerabilities = ConsolidateVulnerabilities(pkg.Vulnerabilities)
		after += len(pkg.Vulnerabilities)
	}
	return before, after
}

// Merge folds every package from other into r.
func (r *PackageRegistry) Merge(other *PackageRegistry) {
	if r == nil || other == nil {
		return
	}
	for _, purl := range other.order {
		r.Add(other.byPURL[purl])
	}
}
