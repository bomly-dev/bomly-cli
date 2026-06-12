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
	normalizePackageURLParts(parsed)
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
	normalizePackageURLParts(purl)
	if err := purl.Normalize(); err != nil {
		return buildPackageURLFallback(purlType, namespace, name, version)
	}
	return purl.ToString()
}

func normalizePackageURLParts(purl *packageurl.PackageURL) {
	if purl == nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(purl.Type), "npm") {
		namespace := strings.TrimSpace(purl.Namespace)
		if namespace != "" && !strings.HasPrefix(namespace, "@") && !strings.HasPrefix(strings.ToLower(namespace), "%40") {
			purl.Namespace = "@" + namespace
		}
	}
}

func buildPackageURLFallback(purlType, namespace, name, version string) string {
	var builder strings.Builder
	builder.WriteString("pkg:")
	builder.WriteString(purlType)
	builder.WriteString("/")
	if namespace != "" {
		builder.WriteString(namespace)
		builder.WriteString("/")
	}
	builder.WriteString(name)
	if version != "" {
		builder.WriteString("@")
		builder.WriteString(version)
	}
	return builder.String()
}

// PackageURLTypeForValues maps ecosystem/build-system values to a package-url type.
func PackageURLTypeForValues(values ...any) string {
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(packageURLTypeValue(value)))
		switch normalized {
		case "nuget":
			return "nuget"
		case "cargo":
			return "cargo"
		case "pub":
			return "pub"
		case "cocoapods":
			return "cocoapods"
		case "swiftpm":
			return "swift"
		case "github-actions", "githubactions":
			return "githubactions"
		case "conan":
			return "conan"
		case "mix", "hex":
			return "hex"
		case "sbt", "scala":
			return "maven"
		case "ruby", "gem", "rubygems", "bundler":
			return "gem"
		case "php", "composer":
			return "composer"
		case "python", "pypi", "pip", "pipenv", "poetry", "uv":
			return "pypi"
		}
	}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(packageURLTypeValue(value)))
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

func packageURLTypeValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case Ecosystem:
		return string(v)
	case PackageManager:
		return v.Name()
	case PackageType:
		return string(v)
	case Language:
		return string(v)
	default:
		return ""
	}
}

// CanonicalPackageURLFromParts returns the canonical package URL derived from
// raw identity fields. existingPURL takes precedence when it canonicalizes.
func CanonicalPackageURLFromParts(existingPURL string, ecosystem Ecosystem, packageManager PackageManager, typ PackageType, org, name, version string) string {
	if canonical := CanonicalizePackageURL(existingPURL); canonical != "" {
		return canonical
	}
	if typ == PackageTypeManifest {
		return ""
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	purlType := PackageURLTypeForValues(ecosystem, packageManager, typ)
	namespace := strings.TrimSpace(org)
	if purlType == "golang" && namespace == "" {
		parts := strings.Split(strings.ReplaceAll(name, "\\", "/"), "/")
		if len(parts) > 1 {
			namespace = strings.Join(parts[:len(parts)-1], "/")
			name = parts[len(parts)-1]
		}
	}

	return BuildPackageURL(purlType, namespace, name, version)
}

// CanonicalPackageURLFromDependency returns the canonical package URL for dep.
func CanonicalPackageURLFromDependency(dep *Dependency) string {
	if dep == nil {
		return ""
	}
	return CanonicalPackageURLFromParts(dep.PURL, dep.Ecosystem, dep.PackageManager, dep.Type, dep.Org, dep.Name, dep.Version)
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
