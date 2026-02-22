package sdk

import (
	"strings"

	"github.com/anchore/packageurl-go"
)

// ParsePackageURL parses a package URL string.
func ParsePackageURL(value string) *packageurl.PackageURL {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := packageurl.FromString(value)
	if err != nil {
		return nil
	}
	return &parsed
}

// CanonicalizePackageURL normalizes a package URL string when possible.
func CanonicalizePackageURL(value string) string {
	parsed := ParsePackageURL(value)
	if parsed == nil {
		return ""
	}
	if err := parsed.Normalize(); err != nil {
		return ""
	}
	return parsed.ToString()
}

// BuildPackageURL builds and normalizes a package URL from its parts.
func BuildPackageURL(purlType, namespace, name, version string) string {
	purlType = strings.TrimSpace(strings.ToLower(purlType))
	name = strings.Trim(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"), "/")
	namespace = strings.Trim(strings.ReplaceAll(strings.TrimSpace(namespace), "\\", "/"), "/")
	version = strings.TrimSpace(version)
	if purlType == "" || name == "" {
		return ""
	}
	purl := packageurl.NewPackageURL(purlType, namespace, name, version, nil, "")
	if purl == nil {
		return ""
	}
	if err := purl.Normalize(); err != nil {
		return ""
	}
	return purl.ToString()
}

// PackageURLTypeForValues maps ecosystem/build-system values to a package-url type.
func PackageURLTypeForValues(values ...string) string {
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		switch normalized {
		case "go", "gomod":
			return "golang"
		default:
			return normalized
		}
	}
	return "generic"
}

// CanonicalPackageURLFromPackage returns the canonical package URL for pkg.
func CanonicalPackageURLFromPackage(pkg *Package) string {
	if pkg == nil {
		return ""
	}
	if canonical := CanonicalizePackageURL(pkg.PURL); canonical != "" {
		return canonical
	}
	if strings.EqualFold(strings.TrimSpace(pkg.Type), "manifest") {
		return ""
	}

	name := strings.TrimSpace(pkg.Name)
	if name == "" {
		return ""
	}

	purlType := PackageURLTypeForValues(pkg.Ecosystem, pkg.BuildSystem, pkg.Type)
	namespace := strings.TrimSpace(pkg.Org)
	if purlType == "golang" && namespace == "" {
		parts := strings.Split(strings.ReplaceAll(name, "\\", "/"), "/")
		if len(parts) > 1 {
			namespace = strings.Join(parts[:len(parts)-1], "/")
			name = parts[len(parts)-1]
		}
	}

	return BuildPackageURL(purlType, namespace, name, pkg.Version)
}

// PackageURLBase strips version and qualifiers from a package URL.
func PackageURLBase(value string) string {
	value = CanonicalizePackageURL(value)
	if value == "" {
		return ""
	}
	if q := strings.Index(value, "?"); q >= 0 {
		value = value[:q]
	}
	at := strings.LastIndex(value, "@")
	if at <= 0 {
		return value
	}
	return value[:at]
}
