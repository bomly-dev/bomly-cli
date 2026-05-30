package sdk

import (
	"fmt"
	"sort"
	"strings"
)

// Scope describes the normalized dependency scope surfaced to users.
type Scope string

const (
	// ScopeUnknown indicates that a detector could not determine dependency scope.
	ScopeUnknown Scope = ""
	// ScopeRuntime indicates a dependency required at runtime.
	ScopeRuntime Scope = "runtime"
	// ScopeDevelopment indicates a dependency used only for development workflows.
	ScopeDevelopment Scope = "development"
)

// ParseScope normalizes a user-provided dependency scope value.
func ParseScope(value string) (Scope, error) {
	switch Scope(strings.ToLower(strings.TrimSpace(value))) {
	case ScopeRuntime:
		return ScopeRuntime, nil
	case ScopeDevelopment:
		return ScopeDevelopment, nil
	case ScopeUnknown:
		return ScopeUnknown, nil
	default:
		return ScopeUnknown, fmt.Errorf("unsupported scope %q", value)
	}
}

// MergeScope combines two normalized scopes, preferring runtime when a package
// is reachable from both runtime and development roots.
func MergeScope(current, next Scope) Scope {
	switch {
	case next == ScopeUnknown:
		return current
	case current == ScopeUnknown:
		return next
	case current == ScopeRuntime || next == ScopeRuntime:
		return ScopeRuntime
	default:
		return ScopeDevelopment
	}
}

// DependencyQuery identifies a specific component target.
type DependencyQuery struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}

// ScopesOf returns a one-element scope slice for a non-unknown scope, or nil.
// Convenience for detectors building Dependency literals from a single scope.
func ScopesOf(scopes ...Scope) []Scope {
	out := make([]Scope, 0, len(scopes))
	for _, s := range scopes {
		if s == ScopeUnknown {
			continue
		}
		dup := false
		for _, existing := range out {
			if existing == s {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Dependency is one node in a manifest's directed dependency graph: a detected
// dependency instance with identity, detection metadata, and a reference to its
// matching artifact (Package) by PURL. Matching enrichment (licenses,
// vulnerabilities, scorecard) lives on the referenced Package, not here.
type Dependency struct {
	ID          string            `json:"id"`
	Name        string            `json:"name,omitempty"`
	Version     string            `json:"version,omitempty"`
	PURL        string            `json:"purl,omitempty"`
	Ecosystem   string            `json:"ecosystem,omitempty"`
	Type        string            `json:"type,omitempty"`
	Org         string            `json:"org,omitempty"`
	BuildSystem string            `json:"build_system,omitempty"`
	Language    string            `json:"language,omitempty"`
	Scopes      []Scope           `json:"scopes,omitempty"`
	Locations   []PackageLocation `json:"locations,omitempty"`
	CPEs        []string          `json:"cpes,omitempty"`
	Digests     []Digest          `json:"digests,omitempty"`
	Copyright   string            `json:"copyright,omitempty"`
	FoundBy     string            `json:"found_by,omitempty"`
	ResolvedURL string            `json:"resolved_url,omitempty"`
	Metadata    map[string]any    `json:"metadata,omitempty"`

	// Matched is true when the referenced package was enriched by a matcher.
	Matched bool `json:"matched,omitempty"`
	// PackageRef is the PURL of this dependency's matching artifact.
	PackageRef string `json:"package_ref,omitempty"`
}

// QualifiedName returns the name prefixed with its organization when present.
func (d *Dependency) QualifiedName() string {
	if d == nil {
		return ""
	}
	return qualifiedName(d.Org, d.Name)
}

// DisplayName returns the most human-friendly identifier available.
func (d *Dependency) DisplayName() string {
	if d == nil {
		return ""
	}
	if name := d.QualifiedName(); name != "" {
		return name
	}
	return d.ID
}

// StableID returns the stable graph identifier for the dependency.
func (d *Dependency) StableID() string {
	if d == nil {
		return ""
	}
	base := d.QualifiedName()
	if d.Version == "" {
		return base
	}
	if base == "" {
		return d.Version
	}
	return fmt.Sprintf("%s@%s", base, d.Version)
}

// IdentityKey returns a stable identity without version information.
func (d *Dependency) IdentityKey() string {
	if d == nil {
		return ""
	}
	return strings.Join([]string{d.Ecosystem, d.BuildSystem, d.Type, d.Org, d.Name}, "\x00")
}

// PrimaryScope returns the merged precedence scope across all recorded scopes.
func (d *Dependency) PrimaryScope() Scope {
	if d == nil {
		return ScopeUnknown
	}
	result := ScopeUnknown
	for _, scope := range d.Scopes {
		result = MergeScope(result, scope)
	}
	return result
}

// HasScope reports whether the dependency carries the given scope.
func (d *Dependency) HasScope(scope Scope) bool {
	if d == nil {
		return false
	}
	for _, s := range d.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// AddScope records a scope on the dependency if not already present.
func (d *Dependency) AddScope(scope Scope) {
	if d == nil || scope == ScopeUnknown || d.HasScope(scope) {
		return
	}
	d.Scopes = append(d.Scopes, scope)
	sort.Slice(d.Scopes, func(i, j int) bool { return d.Scopes[i] < d.Scopes[j] })
}

// Clone returns a deep copy of the dependency.
func (d *Dependency) Clone() *Dependency {
	if d == nil {
		return nil
	}
	clone := *d
	if len(d.Scopes) > 0 {
		clone.Scopes = append([]Scope(nil), d.Scopes...)
	}
	clone.CPEs = cloneStrings(d.CPEs)
	if len(d.Digests) > 0 {
		clone.Digests = append([]Digest(nil), d.Digests...)
	}
	if len(d.Locations) > 0 {
		clone.Locations = make([]PackageLocation, len(d.Locations))
		for i, loc := range d.Locations {
			clone.Locations[i] = loc
			if loc.Position != nil {
				pos := *loc.Position
				clone.Locations[i].Position = &pos
			}
		}
	}
	clone.Metadata = cloneAnyMap(d.Metadata)
	return &clone
}

// WithoutID returns the dependency data without the precomputed graph ID.
func (d *Dependency) WithoutID() Dependency {
	if d == nil {
		return Dependency{}
	}
	clone := d.Clone()
	clone.ID = ""
	return *clone
}

// NewDependency constructs a dependency node, deriving its ID from identity.
func NewDependency(dep Dependency) *Dependency {
	return NewDependencyWithID(dep.StableID(), dep)
}

// NewDependencyWithID constructs a dependency node with a custom ID.
func NewDependencyWithID(id string, dep Dependency) *Dependency {
	clone := dep.Clone()
	clone.ID = id
	return clone
}

// NewDependencyRef constructs a dependency from a name and version. If version
// is set, ID is "name@version"; otherwise ID is "name".
func NewDependencyRef(name, version string) *Dependency {
	return NewDependency(Dependency{Name: name, Version: version})
}

// NewDependencyRefWithID constructs a dependency with a custom ID.
func NewDependencyRefWithID(id, name, version string) *Dependency {
	return NewDependencyWithID(id, Dependency{Name: name, Version: version})
}
