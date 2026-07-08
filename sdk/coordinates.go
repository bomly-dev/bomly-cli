package sdk

import "strings"

// Coordinates is the shared identity view embedded by Dependency and Package.
// It intentionally excludes graph-only fields (scopes, locations, package refs)
// and enrichment-only fields (licenses, vulnerabilities, scorecard) so
// detection-time graph nodes and matching-stage package records remain distinct
// domain models.
type Coordinates struct {
	PURL           string         `json:"purl,omitempty"`
	Ecosystem      Ecosystem      `json:"ecosystem,omitempty"`
	PackageManager PackageManager `json:"package_manager,omitempty"`
	Type           PackageType    `json:"type,omitempty"`
	Org            string         `json:"org,omitempty"`
	Name           string         `json:"name,omitempty"`
	Version        string         `json:"version,omitempty"`
	Language       Language       `json:"language,omitempty"`
}

// QualifiedName returns the package name prefixed with its organization when present.
func (i Coordinates) QualifiedName() string {
	return qualifiedName(i.Org, i.Name)
}

// DisplayName returns the package name in its ecosystem-native form:
// "@org/name" for npm-family packages, "org/name" for path-style ecosystems
// (Go, Composer), and "org:name" otherwise. Unlike QualifiedName it is a
// presentation label only and must never be used as an identity key.
func (i Coordinates) DisplayName() string {
	if i.Org == "" || i.Name == "" {
		return qualifiedName(i.Org, i.Name)
	}
	switch i.displayEcosystem() {
	case EcosystemNPM:
		return "@" + i.Org + "/" + i.Name
	case EcosystemGo, EcosystemPHP:
		return i.Org + "/" + i.Name
	default:
		return i.Org + ":" + i.Name
	}
}

// displayEcosystem resolves the effective ecosystem for display formatting,
// falling back to the package-manager name when Ecosystem is unset (e.g.
// pnpm/yarn graphs that only carry a manager identifier).
func (i Coordinates) displayEcosystem() Ecosystem {
	for _, candidate := range []string{string(i.Ecosystem), i.PackageManager.Name(), string(i.Type)} {
		switch strings.ToLower(strings.TrimSpace(candidate)) {
		case string(EcosystemNPM), "pnpm", "yarn", "bun":
			return EcosystemNPM
		case string(EcosystemGo), "gomod", "golang":
			return EcosystemGo
		case string(EcosystemPHP), "composer", "packagist":
			return EcosystemPHP
		}
	}
	return i.Ecosystem
}

// StableID returns a graph-friendly identifier derived from name and version.
func (i Coordinates) StableID() string {
	base := i.QualifiedName()
	if i.Version == "" {
		return base
	}
	if base == "" {
		return i.Version
	}
	return base + "@" + i.Version
}

// IdentityKey returns a stable package identity without version information.
func (i Coordinates) IdentityKey() string {
	return strings.Join([]string{string(i.Ecosystem), i.PackageManager.Name(), string(i.Type), i.Org, i.Name}, "\x00")
}
