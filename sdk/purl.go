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
//
// The explicit switch below is the authority: it is consulted for every value
// before the loose fallback runs, so the most specific mapping wins regardless
// of the order the caller passes ecosystem / package manager / package type in.
// The fallback then returns the first non-empty value verbatim, which is only
// correct where the Bomly identifier happens to be the purl type as well (npm,
// maven, apk, rpm, ...). Any ecosystem whose purl type differs from its Bomly
// name needs an explicit case here — without one we emit a type that is not in
// the purl spec, and consumers keyed on the type (OSV, SBOM ingest) silently
// fail to match. See issue #317.
//
// Ecosystems that span more than one registry are the exception: erlang covers
// both Hex (rebar) and OTP (*.app), so it is mapped at the package-manager
// level only. A bare erlang value with no manager to disambiguate keeps the
// non-spec pkg:erlang rather than guessing a registry the package may not be
// published to.
func PackageURLTypeForValues(values ...any) string {
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(packageURLTypeValue(value)))
		switch normalized {
		case "nuget", "dotnet":
			return "nuget"
		case "cargo", "rust":
			return "cargo"
		case "pub", "dart":
			return "pub"
		case "cocoapods":
			// Deliberately no "swift" case: swift is itself a purl type, and
			// adding one here would beat cocoapods whenever the ecosystem is
			// checked before the package manager.
			return "cocoapods"
		case "swiftpm":
			return "swift"
		case "github-actions", "githubactions":
			return "githubactions"
		case "conan", "cpp":
			return "conan"
		case "mix", "hex", "elixir", "rebar":
			// Elixir (mix) and Erlang (rebar) both resolve from Hex.
			return "hex"
		case "otp":
			// OTP applications are discovered from *.app manifests. They ship
			// with the runtime or the release rather than resolving from Hex,
			// so they get their own type — the same one Syft emits for them.
			// Claiming Hex here would let a name collision with a real Hex
			// package produce a false advisory match.
			return "otp"
		case "haskell", "cabal", "stack", "hackage":
			return "hackage"
		case "r", "r-package", "cran":
			return "cran"
		case "ocaml", "opam":
			return "opam"
		case "dpkg", "deb":
			return "deb"
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
	return (Coordinates{
		PURL:           existingPURL,
		Ecosystem:      ecosystem,
		PackageManager: packageManager,
		Type:           typ,
		Org:            org,
		Name:           name,
		Version:        version,
	}).CanonicalPURL()
}

// CanonicalPURL returns the canonical package URL for the identity.
func (i Coordinates) CanonicalPURL() string {
	if canonical := CanonicalizePackageURL(i.PURL); canonical != "" {
		return canonical
	}
	if i.Type == PackageTypeManifest {
		return ""
	}

	name := strings.TrimSpace(i.Name)
	if name == "" {
		return ""
	}

	purlType := PackageURLTypeForValues(i.Ecosystem, i.PackageManager, i.Type)
	namespace := strings.TrimSpace(i.Org)
	if purlType == "golang" && namespace == "" {
		parts := strings.Split(strings.ReplaceAll(name, "\\", "/"), "/")
		if len(parts) > 1 {
			namespace = strings.Join(parts[:len(parts)-1], "/")
			name = parts[len(parts)-1]
		}
	}

	return BuildPackageURL(purlType, namespace, name, i.Version)
}

// CanonicalPackageURLFromDependency returns the canonical package URL for dep.
func CanonicalPackageURLFromDependency(dep *Dependency) string {
	if dep == nil {
		return ""
	}
	return dep.CanonicalPURL()
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
