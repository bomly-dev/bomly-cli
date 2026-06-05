package sdk

import (
	"strings"
	"unicode"
)

const (
	normMetadataAppliedKey         = "bomly.normalization.applied"
	normMetadataOriginalNameKey    = "bomly.normalization.original_name"
	normMetadataOriginalOrgKey     = "bomly.normalization.original_org"
	normMetadataOriginalVersionKey = "bomly.normalization.original_version"
)

// NormalizeDependencyIdentity applies ecosystem-aware identity normalization in place.
func NormalizeDependencyIdentity(pkg *Dependency) {
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
	if canonicalPURL := CanonicalizePackageURL(pkg.PURL); canonicalPURL != "" && canonicalPURL != pkg.PURL {
		pkg.PURL = canonicalPURL
		applied = append(applied, "purl")
	}

	switch normEffectiveEcosystem(pkg) {
	case string(EcosystemNPM):
		applied = append(applied, normNPM(pkg)...)
	case string(EcosystemPython):
		applied = append(applied, normPython(pkg)...)
	case string(EcosystemRust):
		applied = append(applied, normRust(pkg)...)
	case string(EcosystemMaven):
		applied = append(applied, normMaven(pkg)...)
	case string(EcosystemGo):
		applied = append(applied, normGo(pkg)...)
	case string(EcosystemPHP):
		applied = append(applied, normComposer(pkg)...)
	}

	if normalizedVersion, changed := normVersion(pkg.Version); changed {
		pkg.Version = normalizedVersion
		applied = append(applied, "version")
	}

	normRecordMetadata(pkg, applied, originalName, originalOrg, originalVersion)
}

func normNPM(pkg *Dependency) []string {
	applied := make([]string, 0, 2)
	if scope, name, ok := normSplitScopedNPMName(pkg.Name); ok {
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

func normPython(pkg *Dependency) []string {
	normalized := normCanonicalizePythonName(pkg.Name)
	if normalized == pkg.Name {
		return nil
	}
	pkg.Name = normalized
	return []string{"name"}
}

func normRust(pkg *Dependency) []string {
	normalized := normCollapseRepeated(strings.ToLower(strings.ReplaceAll(pkg.Name, "_", "-")), '-')
	if normalized == pkg.Name {
		return nil
	}
	pkg.Name = normalized
	return []string{"name"}
}

func normMaven(pkg *Dependency) []string {
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

func normGo(pkg *Dependency) []string {
	applied := make([]string, 0, 2)
	if normalizedOrg := normNormalizeSlashPath(pkg.Org); normalizedOrg != pkg.Org {
		pkg.Org = normalizedOrg
		applied = append(applied, "org")
	}
	if normalizedName := normNormalizeSlashPath(pkg.Name); normalizedName != pkg.Name {
		pkg.Name = normalizedName
		applied = append(applied, "name")
	}
	return applied
}

func normComposer(pkg *Dependency) []string {
	if len(pkg.Version) > 1 && (pkg.Version[0] == 'v' || pkg.Version[0] == 'V') {
		pkg.Version = pkg.Version[1:]
		return []string{"version"}
	}
	return nil
}

func normEffectiveEcosystem(pkg *Dependency) string {
	if pkg == nil {
		return ""
	}
	for _, candidate := range []string{pkg.Ecosystem, pkg.BuildSystem, pkg.Type} {
		switch strings.ToLower(strings.TrimSpace(candidate)) {
		case string(EcosystemNPM), "pnpm", "yarn":
			return string(EcosystemNPM)
		case string(EcosystemPython), "pip", "pipenv", "poetry", "uv", "setup.py", "pypi":
			return string(EcosystemPython)
		case string(EcosystemRust), "cargo":
			return string(EcosystemRust)
		case string(EcosystemGo), "gomod", "golang":
			return string(EcosystemGo)
		case string(EcosystemMaven), "gradle":
			return string(EcosystemMaven)
		case string(EcosystemDotNet), "nuget":
			return string(EcosystemDotNet)
		case string(EcosystemDart), "pub":
			return string(EcosystemDart)
		case string(EcosystemSwift), "cocoapods", "swiftpm":
			return string(EcosystemSwift)
		case string(EcosystemCPP), "conan":
			return string(EcosystemCPP)
		case string(EcosystemElixir), "mix", "hex":
			return string(EcosystemElixir)
		case string(EcosystemScala), "sbt":
			return string(EcosystemScala)
		case string(EcosystemPHP), "composer":
			return string(EcosystemPHP)
		case string(EcosystemRuby), "gem", "bundler", "rubygems":
			return string(EcosystemRuby)
		}
	}
	return ""
}

func normSplitScopedNPMName(name string) (string, string, bool) {
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

func normCanonicalizePythonName(name string) string {
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
	return normCollapseRepeated(strings.Trim(replaced, "-"), '-')
}

func normNormalizeSlashPath(value string) string {
	trimmed := strings.Trim(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"), "/")
	for strings.Contains(trimmed, "//") {
		trimmed = strings.ReplaceAll(trimmed, "//", "/")
	}
	return trimmed
}

func normVersion(version string) (string, bool) {
	trimmed := strings.TrimSpace(version)
	if trimmed == "" {
		return "", trimmed != version
	}
	if !normContainsAlpha(trimmed) {
		return trimmed, trimmed != version
	}
	normalized := strings.ToLower(trimmed)
	return normalized, normalized != version
}

func normContainsAlpha(value string) bool {
	for _, r := range value {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func normCollapseRepeated(value string, separator rune) string {
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

func normRecordMetadata(pkg *Dependency, applied []string, originalName, originalOrg, originalVersion string) {
	if pkg == nil || len(applied) == 0 {
		return
	}
	if pkg.Metadata == nil {
		pkg.Metadata = make(map[string]any, 4)
	}
	pkg.Metadata[normMetadataAppliedKey] = normUniqueStrings(applied)
	if pkg.Name != originalName {
		pkg.Metadata[normMetadataOriginalNameKey] = originalName
	}
	if pkg.Org != originalOrg {
		pkg.Metadata[normMetadataOriginalOrgKey] = originalOrg
	}
	if pkg.Version != originalVersion {
		pkg.Metadata[normMetadataOriginalVersionKey] = originalVersion
	}
}

func normUniqueStrings(values []string) []string {
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
