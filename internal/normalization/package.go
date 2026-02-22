package normalization

import (
	"strings"
	"unicode"

	"github.com/bomly/bomly-cli/internal/model"
)

const (
	metadataAppliedKey         = "bomly.normalization.applied"
	metadataOriginalNameKey    = "bomly.normalization.original_name"
	metadataOriginalOrgKey     = "bomly.normalization.original_org"
	metadataOriginalVersionKey = "bomly.normalization.original_version"
)

// NormalizePackageIdentity applies ecosystem-aware package normalization in place.
func NormalizePackageIdentity(pkg *model.Package) {
	if pkg == nil {
		return
	}

	originalName := pkg.Name
	originalOrg := pkg.Org
	originalVersion := pkg.Version
	applied := make([]string, 0, 4)

	pkg.Name = strings.TrimSpace(pkg.Name)
	pkg.Org = strings.TrimSpace(pkg.Org)
	pkg.Version = strings.TrimSpace(pkg.Version)
	pkg.PURL = strings.TrimSpace(pkg.PURL)

	switch effectiveEcosystem(pkg) {
	case string(model.EcosystemNPM):
		applied = append(applied, normalizeNPM(pkg)...)
	case string(model.EcosystemPython):
		applied = append(applied, normalizePython(pkg)...)
	case string(model.EcosystemRust):
		applied = append(applied, normalizeRust(pkg)...)
	case string(model.EcosystemMaven):
		applied = append(applied, normalizeMaven(pkg)...)
	case string(model.EcosystemGo):
		applied = append(applied, normalizeGo(pkg)...)
	}

	if normalizedVersion, changed := normalizeVersion(pkg.Version); changed {
		pkg.Version = normalizedVersion
		applied = append(applied, "version")
	}

	recordMetadata(pkg, applied, originalName, originalOrg, originalVersion)
}

func normalizeNPM(pkg *model.Package) []string {
	applied := make([]string, 0, 2)
	if scope, name, ok := splitScopedNPMName(pkg.Name); ok {
		pkg.Org = scope
		pkg.Name = name
		applied = append(applied, "npm-scope")
	}
	if normalizedOrg := strings.TrimPrefix(strings.ToLower(pkg.Org), "@"); normalizedOrg != pkg.Org {
		pkg.Org = normalizedOrg
		applied = append(applied, "org")
	}
	if normalizedName := strings.ToLower(pkg.Name); normalizedName != pkg.Name {
		pkg.Name = normalizedName
		applied = append(applied, "name")
	}
	return applied
}

func normalizePython(pkg *model.Package) []string {
	normalized := canonicalizePythonName(pkg.Name)
	if normalized == pkg.Name {
		return nil
	}
	pkg.Name = normalized
	return []string{"name"}
}

func normalizeRust(pkg *model.Package) []string {
	normalized := collapseRepeated(strings.ToLower(strings.ReplaceAll(pkg.Name, "_", "-")), '-')
	if normalized == pkg.Name {
		return nil
	}
	pkg.Name = normalized
	return []string{"name"}
}

func normalizeMaven(pkg *model.Package) []string {
	applied := make([]string, 0, 2)
	if normalizedOrg := strings.ToLower(pkg.Org); normalizedOrg != pkg.Org {
		pkg.Org = normalizedOrg
		applied = append(applied, "org")
	}
	if normalizedName := strings.TrimSpace(pkg.Name); normalizedName != pkg.Name {
		pkg.Name = normalizedName
		applied = append(applied, "name")
	}
	return applied
}

func normalizeGo(pkg *model.Package) []string {
	applied := make([]string, 0, 2)
	if normalizedOrg := normalizeSlashPath(pkg.Org); normalizedOrg != pkg.Org {
		pkg.Org = normalizedOrg
		applied = append(applied, "org")
	}
	if normalizedName := normalizeSlashPath(pkg.Name); normalizedName != pkg.Name {
		pkg.Name = normalizedName
		applied = append(applied, "name")
	}
	return applied
}

func effectiveEcosystem(pkg *model.Package) string {
	if pkg == nil {
		return ""
	}
	for _, candidate := range []string{pkg.Ecosystem, pkg.BuildSystem, pkg.Type} {
		switch strings.ToLower(strings.TrimSpace(candidate)) {
		case string(model.EcosystemNPM), "pnpm", "yarn":
			return string(model.EcosystemNPM)
		case string(model.EcosystemPython), "pip", "pipenv", "poetry", "uv", "setup.py", "pypi":
			return string(model.EcosystemPython)
		case string(model.EcosystemRust), "cargo":
			return string(model.EcosystemRust)
		case string(model.EcosystemGo), "gomod", "golang":
			return string(model.EcosystemGo)
		case string(model.EcosystemMaven), "gradle":
			return string(model.EcosystemMaven)
		}
	}
	return ""
}

func splitScopedNPMName(name string) (string, string, bool) {
	trimmed := strings.TrimSpace(name)
	if !strings.HasPrefix(trimmed, "@") {
		return "", "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(trimmed, "@"), "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func canonicalizePythonName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return ""
	}
	replaced := strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == '_' || r == '.' || unicode.IsSpace(r):
			return '-'
		default:
			return unicode.ToLower(r)
		}
	}, lower)
	return collapseRepeated(strings.Trim(replaced, "-"), '-')
}

func normalizeSlashPath(value string) string {
	trimmed := strings.Trim(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"), "/")
	for strings.Contains(trimmed, "//") {
		trimmed = strings.ReplaceAll(trimmed, "//", "/")
	}
	return trimmed
}

func normalizeVersion(version string) (string, bool) {
	trimmed := strings.TrimSpace(version)
	if trimmed == "" {
		return "", trimmed != version
	}
	if !containsAlpha(trimmed) {
		return trimmed, trimmed != version
	}
	normalized := strings.ToLower(trimmed)
	return normalized, normalized != version
}

func containsAlpha(value string) bool {
	for _, r := range value {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func collapseRepeated(value string, separator rune) string {
	if value == "" {
		return value
	}
	var builder strings.Builder
	builder.Grow(len(value))
	lastWasSeparator := false
	for _, r := range value {
		if r == separator {
			if lastWasSeparator {
				continue
			}
			lastWasSeparator = true
		} else {
			lastWasSeparator = false
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

func recordMetadata(pkg *model.Package, applied []string, originalName, originalOrg, originalVersion string) {
	if pkg == nil || len(applied) == 0 {
		return
	}
	if pkg.Metadata == nil {
		pkg.Metadata = make(map[string]any, 4)
	}
	pkg.Metadata[metadataAppliedKey] = uniqueStrings(applied)
	if pkg.Name != originalName {
		pkg.Metadata[metadataOriginalNameKey] = originalName
	}
	if pkg.Org != originalOrg {
		pkg.Metadata[metadataOriginalOrgKey] = originalOrg
	}
	if pkg.Version != originalVersion {
		pkg.Metadata[metadataOriginalVersionKey] = originalVersion
	}
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}