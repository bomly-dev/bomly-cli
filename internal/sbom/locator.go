package sbom

import (
	"net/url"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// LocatorKind classifies what a detector-supplied resolved URL actually points
// at. Detectors record wildly different things in the same field — an npm
// lockfile records a tarball URL, a Gemfile.lock records the registry root, a
// uv lock can record a local directory — so the kind must be decided per value
// rather than per ecosystem.
type LocatorKind int

const (
	// LocatorNone means nothing publishable could be asserted. Local
	// filesystem paths and credential-bearing URLs land here.
	LocatorNone LocatorKind = iota
	// LocatorArtifact is a concrete downloadable file.
	LocatorArtifact
	// LocatorVCS is a source-control location.
	LocatorVCS
	// LocatorRegistryRoot is a registry or index root: it says where the
	// ecosystem fetches from, not where this package came from.
	LocatorRegistryRoot
)

// Locator is the classified form of a resolved URL, ready for projection into
// an SBOM. URL is empty whenever Kind is LocatorNone.
type Locator struct {
	Kind LocatorKind
	URL  string
}

// artifactExtensions are the archive suffixes that mark a URL path as a
// concrete package artifact rather than a registry endpoint. The list is an
// allowlist on purpose: an unrecognized path shape degrades to a registry
// root, which is never used as a download location.
var artifactExtensions = []string{
	".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar", ".zip",
	".whl", ".gem", ".crate", ".jar", ".nupkg", ".egg", ".conda",
}

// classifyResolvedURL decides what raw points at, given the detector's own
// source classification and the package ecosystem.
//
// The function is deliberately conservative: it emits nothing unless the value
// is an unambiguous http(s) URL, and it prefers the weaker LocatorRegistryRoot
// over LocatorArtifact whenever the path shape is not recognizably an archive.
// An SBOM that omits a download location is correct; one that points at the
// wrong place, or at the developer's home directory, is not.
func classifyResolvedURL(raw string, source sdk.DependencySource, ecosystem sdk.Ecosystem) Locator {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Locator{}
	}

	// Cargo records the raw Cargo.lock `source` string, which carries its own
	// scheme prefix. The prefix is a stronger signal than anything else here.
	hint := LocatorNone
	switch {
	case strings.HasPrefix(raw, "registry+"):
		raw, hint = strings.TrimPrefix(raw, "registry+"), LocatorRegistryRoot
	case strings.HasPrefix(raw, "sparse+"):
		raw, hint = strings.TrimPrefix(raw, "sparse+"), LocatorRegistryRoot
	case strings.HasPrefix(raw, "git+"):
		raw, hint = strings.TrimPrefix(raw, "git+"), LocatorVCS
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return Locator{}
	}

	// The scheme gate is what keeps local filesystem layout out of published
	// SBOMs. Several detectors put bare paths in this field (uv `editable`
	// and `path`, pipenv `path`, pub `path`, npm link entries), and they do
	// not consistently carry DependencySourceFile, so the check must be on
	// the value rather than on source.
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return Locator{}
	}
	if parsed.Host == "" {
		return Locator{}
	}

	// A lockfile pointing at a private registry can embed a token. Publishing
	// it in an SBOM would leak a live credential, so drop the value entirely
	// rather than try to strip the userinfo and emit the rest.
	if parsed.User != nil {
		return Locator{}
	}

	switch source {
	case sdk.DependencySourceFile, sdk.DependencySourceProject, sdk.DependencySourceWorkspace:
		return Locator{}
	}

	if hint == LocatorVCS {
		return normalizeVCS(parsed)
	}

	// Credentials also travel outside userinfo: signed and private-registry
	// URLs carry them as query parameters or fragments
	// ("...?token=<secret>", "...?X-Amz-Signature=..."). A benign query
	// parameter cannot be told apart from a credential here, so any query or
	// fragment disqualifies a non-VCS locator. VCS locators are exempt
	// because normalizeVCS discards both, keeping only a character-checked
	// revision.
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return Locator{}
	}

	if hint == LocatorRegistryRoot {
		return Locator{Kind: LocatorRegistryRoot, URL: parsed.String()}
	}

	// Swift package identity is the repository URL, so swiftpm records a repo
	// even for `kind: registry` pins. Without this the extension check below
	// would demote them to registry roots.
	if ecosystem == sdk.EcosystemSwift {
		return normalizeVCS(parsed)
	}

	if source == sdk.DependencySourceGit || strings.HasSuffix(parsed.Path, ".git") {
		return normalizeVCS(parsed)
	}

	if isConcreteArtifactPath(parsed.Path) {
		return Locator{Kind: LocatorArtifact, URL: parsed.String()}
	}
	return Locator{Kind: LocatorRegistryRoot, URL: parsed.String()}
}

// isConcreteArtifactPath reports whether the final path segment names a
// package archive.
func isConcreteArtifactPath(path string) bool {
	idx := strings.LastIndex(path, "/")
	last := strings.ToLower(path[idx+1:])
	if last == "" {
		return false
	}
	for _, ext := range artifactExtensions {
		if strings.HasSuffix(last, ext) {
			return true
		}
	}
	return false
}

// normalizeVCS renders parsed in the SPDX 2.3 version-control form,
// "<tool>+<transport>://<host><path>[@<revision>]".
//
// That grammar has no query component, so a cargo value such as
// "git+https://host/a/b?rev=abc" cannot be passed through as-is: the revision
// is moved to the "@" suffix and the query is dropped.
func normalizeVCS(parsed *url.URL) Locator {
	revision := ""
	for _, key := range []string{"rev", "tag", "branch"} {
		if value := strings.TrimSpace(parsed.Query().Get(key)); value != "" {
			revision = value
			break
		}
	}
	if revision == "" {
		revision = strings.TrimSpace(parsed.Fragment)
	}

	clean := *parsed
	clean.RawQuery = ""
	clean.Fragment = ""

	// A repository location needs a path: "https://host" alone identifies no
	// repository. Requiring one also removes an ambiguity in the SPDX form —
	// with an empty path, the "@<revision>" suffix would re-parse as URL
	// userinfo ("git+https://host@rev" reads as user "host", host "rev").
	if path := strings.Trim(clean.Path, "/"); path == "" {
		return Locator{}
	}

	base := strings.TrimSuffix(clean.String(), "/")
	out := "git+" + base
	if isSafeRevision(revision) {
		out += "@" + revision
	}
	return Locator{Kind: LocatorVCS, URL: out}
}

// isSafeRevision reports whether revision is a plausible git revision that can
// be appended to an SPDX version-control locator verbatim.
//
// The value originates in a lockfile, so it may contain anything at all; a
// control character or a space would produce an unparseable locator. An
// unsafe revision is dropped rather than escaped, leaving the still-correct
// repository URL without a pinned revision.
func isSafeRevision(revision string) bool {
	if revision == "" || len(revision) > 256 {
		return false
	}
	for _, r := range revision {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-', r == '/', r == '+':
		default:
			return false
		}
	}
	return true
}

// normalizeRepositoryURL renders a scheme-less canonical repository
// identifier, such as the "github.com/owner/repo" the OpenSSF Scorecard
// matcher records, as an absolute https URL.
//
// CycloneDX external reference URLs are iri-reference typed, so a scheme-less
// value would validate but be read as a relative reference. Returns "" when
// the value does not look like a host-qualified repository.
func normalizeRepositoryURL(repo string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" || strings.ContainsAny(repo, " \t\r\n") {
		return ""
	}
	if strings.Contains(repo, "://") {
		parsed, err := url.Parse(repo)
		if err != nil || parsed.User != nil || parsed.Host == "" {
			return ""
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return ""
		}
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https":
			return parsed.String()
		default:
			return ""
		}
	}
	if strings.ContainsAny(repo, "?#") {
		return ""
	}

	host, rest, ok := strings.Cut(repo, "/")
	if !ok || !isHostname(host) || strings.TrimSpace(rest) == "" {
		return ""
	}

	// Re-parse rather than trusting the shape check: the path may still hold
	// something url.Parse rejects, such as an invalid percent-escape.
	candidate := "https://" + repo
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Host != host || parsed.User != nil {
		return ""
	}
	return candidate
}

// classifyIngestedVCS renders a repository URL taken from an ingested SBOM in
// the SPDX version-control form.
//
// CycloneDX permits a plain https repository URL in a `vcs` reference, but
// SPDX 2.3 uses the `git+<transport>` notation and `spdxDownloadLocation`
// emits this value directly — so an unnormalized value would make a repository
// look like an ordinary package download. The value is untrusted, so it goes
// through the same scheme, host, and userinfo gate as a detector-supplied one.
func classifyIngestedVCS(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "git+")
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" {
		return ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return ""
	}
	return normalizeVCS(parsed).URL
}

// classifyAssertedDownloadLocation classifies a value that its source document
// already declared to be a download location, such as SPDX
// PackageDownloadLocation.
//
// The path-shape heuristic that guards detector-supplied values does not apply
// here: an exact endpoint without a recognizable archive suffix
// ("https://repo.example/download?id=123" reduced to its path) would be demoted
// to a registry root and re-exported as NOASSERTION, discarding an assertion
// the source document actually made. The safety gate still applies in full, so
// local paths and credential-bearing URLs are still dropped.
func classifyAssertedDownloadLocation(raw string) Locator {
	locator := classifyResolvedURL(raw, "", "")
	if locator.Kind == LocatorRegistryRoot {
		locator.Kind = LocatorArtifact
	}
	return locator
}

// isPublishableReferenceURL reports whether a URL carried on an ingested
// external reference is safe to re-emit.
//
// Ingested references are re-emitted verbatim, so they need the same gate a
// detector-supplied value gets: no local paths, no credentials in userinfo,
// and no credential-bearing query or fragment. `mailto:` is allowed because a
// security-contact reference is a legitimate, path-free reference target.
func isPublishableReferenceURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return parsed.Host != "" && parsed.RawQuery == "" && parsed.Fragment == ""
	case "mailto":
		return parsed.Opaque != "" && parsed.RawQuery == ""
	default:
		return false
	}
}

// isHostname reports whether value looks like a dotted DNS hostname.
func isHostname(value string) bool {
	if !strings.Contains(value, ".") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}
