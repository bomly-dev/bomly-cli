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

// metadataKeySourceRevision is the Dependency.Metadata key several detectors
// (ruby, pub, and the python family) use to record the commit a git
// dependency resolved to, separately from the repository URL.
// Detectors do not agree on one key: ruby, pub, and the python family write
// "source_revision", while swiftpm writes "revision".
var metadataRevisionKeys = []string{"source_revision", "revision"}

// sourceRevisionFrom returns a detector-recorded resolved commit, or "".
func sourceRevisionFrom(metadata map[string]any) string {
	for _, key := range metadataRevisionKeys {
		revision, _ := metadata[key].(string)
		revision = strings.TrimSpace(revision)
		if isSafeRevision(revision) {
			return revision
		}
	}
	return ""
}

// pinLocator attaches a detector-recorded revision to a VCS locator that does
// not already carry one.
//
// Bundler, pub, and the python detectors keep the resolved commit in metadata
// while leaving ResolvedURL as the bare remote, so without this the export
// would name a moving branch for a dependency whose commit is actually known.
func pinLocator(locator Locator, revision string) Locator {
	if locator.Kind != LocatorVCS || revision == "" {
		return locator
	}
	_, existingRevision, ok := splitVCSRevision(locator.URL)
	if !ok || existingRevision != "" {
		return locator
	}
	return Locator{Kind: LocatorVCS, URL: locator.URL + "@" + revision}
}

// hasCredentialPath reports whether any path segment looks like a secret.
//
// looksLikeCredential is applied to query names and values, revisions, mail
// addresses, and URN segments, but a token can just as easily sit in the path:
// "https://repo.example/download/ghp_abcd1234/pkg.tgz" has no userinfo, no
// query, and no fragment, so every other gate passes it.
func hasCredentialPath(parsed *url.URL) bool {
	path := parsed.Path
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}
	return containsCredential(path) || hasOpaqueSecretRun(path)
}

// hasCredentialHost reports whether any hostname label looks like a secret.
//
// Userinfo, path, query, fragment, and revision positions are all gated, but
// a token can sit in the host too: "https://ghp_abcd1234.repo.example/a.tgz"
// has a nil User, a clean path, and no query, so every other check passes it.
func hasCredentialHost(parsed *url.URL) bool {
	return containsCredential(parsed.Hostname()) || hasOpaqueSecretRun(parsed.Hostname())
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
	vcsTool := ""
	gitArchive := false
	switch {
	case strings.HasPrefix(raw, "registry+"):
		raw, hint = strings.TrimPrefix(raw, "registry+"), LocatorRegistryRoot
	case strings.HasPrefix(raw, "sparse+"):
		raw, hint = strings.TrimPrefix(raw, "sparse+"), LocatorRegistryRoot
	default:
		// Any recognized version-control tool prefix, not just git+: an SPDX
		// downloadLocation of "svn+https://…" is a valid VCS location, and
		// leaving it prefixed makes the transport gate reject it outright.
		// The tool is carried through so normalization does not silently
		// rewrite the asserted version-control system as Git.
		if prefix, rest, isVCS := splitVCSToolPrefix(raw); isVCS {
			raw, hint, vcsTool = rest, LocatorVCS, prefix
		}
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
	// Detector-derived values stay HTTP-only: nothing asserts what they are,
	// so the narrowest gate is right. A value the source document declared a
	// download location may also use the network transports the external
	// reference gate accepts.
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return Locator{}
	}
	if parsed.Hostname() == "" {
		return Locator{}
	}

	// A lockfile pointing at a private registry can embed a token. Publishing
	// it in an SBOM would leak a live credential, so drop the value entirely
	// rather than try to strip the userinfo and emit the rest.
	if parsed.User != nil || hasCredentialHost(parsed) {
		return Locator{}
	}

	switch source {
	case sdk.DependencySourceFile, sdk.DependencySourceProject, sdk.DependencySourceWorkspace:
		return Locator{}
	}

	// Every VCS form is classified before the query and fragment gate below.
	// normalizeVCS discards both and keeps only a character-checked revision,
	// so it is safe on values the gate would otherwise reject — and a git
	// dependency legitimately pins its revision that way
	// ("https://host/repo.git?rev=<sha>"). Gating first would silently drop
	// those pins.
	if hint == LocatorVCS {
		return normalizeVCS(parsed, vcsTool)
	}
	if hint != LocatorRegistryRoot {
		// Swift package identity is the repository URL, so swiftpm records a
		// repo even for `kind: registry` pins. Without this the extension
		// check below would demote them to registry roots.
		if ecosystem == sdk.EcosystemSwift {
			return normalizeVCS(parsed, vcsTool)
		}
		if source == sdk.DependencySourceGit || strings.HasSuffix(parsed.Path, ".git") {
			// A git-sourced dependency can still resolve to an archive: Yarn
			// stores the codeload tarball for a GitHub selector. Rendering
			// that endpoint in git+ syntax would invent a repository that is
			// not cloneable, so an archive-shaped path stays an artifact and
			// falls through to the gates below.
			if !pathContainsArchive(parsed.Path) {
				return normalizeVCS(parsed, vcsTool)
			}
			gitArchive = true
		}
	}

	// The path is checked here rather than above because every VCS branch has
	// already returned: those go through normalizeVCS, which separates the
	// "@<revision>" suffix and then checks what remains, so a bad revision
	// costs only the revision instead of the whole repository.
	if hasCredentialPath(parsed) {
		return Locator{}
	}

	// Credentials also travel outside userinfo: signed and private-registry
	// URLs carry them as query parameters or fragments
	// ("...?token=<secret>", "...?X-Amz-Signature=..."). A detector-supplied
	// value has nothing asserting the URL is a download location, so any
	// query disqualifies it — a benign parameter cannot be told apart from a
	// credential, and omitting is cheap.
	if parsed.RawQuery != "" {
		return Locator{}
	}

	// A fragment is rejected on the same grounds, with one exception: Yarn
	// v1 appends the artifact's own checksum to every `resolved` URL
	// ("...-1.4.0.tgz#71ee51fa..."). That is a fixed-format digest, not a
	// secret, and rejecting it would drop the download location for every
	// package in a Yarn lockfile. Strip it and keep the URL; anything that
	// is not digest-shaped is still treated as a secret.
	if parsed.Fragment != "" {
		if !isChecksumFragment(parsed.Fragment) {
			return Locator{}
		}
		clean := *parsed
		clean.Fragment = ""
		parsed = &clean
	}

	if hint == LocatorRegistryRoot {
		return Locator{Kind: LocatorRegistryRoot, URL: parsed.String()}
	}

	if isConcreteArtifactPath(parsed.Path) || gitArchive {
		return Locator{Kind: LocatorArtifact, URL: parsed.String()}
	}
	return Locator{Kind: LocatorRegistryRoot, URL: parsed.String()}
}

// isChecksumFragment reports whether a URL fragment is a bare hex digest of a
// standard length, the form Yarn v1 and some registries append to an artifact
// URL.
//
// The length allowlist is what keeps this from becoming a hole: an arbitrary
// hex-looking secret of some other length is still rejected as a credential.
func isChecksumFragment(fragment string) bool {
	switch len(fragment) {
	case 32, 40, 64, 96, 128: // md5, sha1, sha256, sha384, sha512
	default:
		return false
	}
	for _, r := range fragment {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// pathContainsArchive reports whether any path segment is archive-shaped —
// either carrying a package-archive extension or being one outright, the way
// codeload URLs embed "tar.gz" as its own segment before the revision.
func pathContainsArchive(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		lowered := strings.ToLower(segment)
		for _, ext := range artifactExtensions {
			if strings.HasSuffix(lowered, ext) || lowered == strings.TrimPrefix(ext, ".") {
				return true
			}
		}
	}
	return false
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
func normalizeVCS(parsed *url.URL, tool string) Locator {
	// The fragment carries the resolved commit and the query carries what was
	// requested, so "?branch=main#abc123" locked abc123. Preferring the
	// fragment records the immutable commit rather than a moving branch, and
	// matches the precedence uvSourceRevision already applies when the same
	// lockfile value is parsed for detection.
	//
	// A fragment must be commit-shaped, not merely character-safe: an access
	// token such as "#ghp_abcd1234" passes isSafeRevision and would then be
	// republished after the "@". A query value is held to the looser rule
	// because its key names it a revision.
	// An already-rendered "@<revision>" lives in the path, where url.Parse
	// leaves it untouched. Splitting it off here is what stops a token from
	// riding through on a value that was normalized once already: this
	// function is reached from paths that never call validatedVCSLocator.
	parsed, pathRevision, ok := splitVCSRevision(parsed.String())
	if !ok {
		return Locator{}
	}

	revision := strings.TrimSpace(parsed.Fragment)
	if !isCommitFragment(revision) {
		revision = ""
	}
	if revision == "" {
		revision = pathRevision
	}
	if revision == "" {
		for _, key := range []string{"rev", "tag", "branch"} {
			if value := strings.TrimSpace(parsed.Query().Get(key)); value != "" {
				revision = value
				break
			}
		}
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
	if tool == "" {
		tool = "git+"
	}
	out := tool + base
	if isSafeRevision(revision) {
		out += "@" + revision
	}
	return Locator{Kind: LocatorVCS, URL: out}
}

// isCommitFragment reports whether a URL fragment looks like a git object
// name.
//
// Fragments on a version-control URL carry the resolved commit by convention
// (uv and cargo both write one), so requiring bare hex is faithful to the
// format and, unlike the looser isSafeRevision, excludes credential shapes:
// "ghp_abcd1234" and "github_pat_11ABC_xyz" both fail on their underscores
// and non-hex letters.
func isCommitFragment(fragment string) bool {
	if len(fragment) < 4 || len(fragment) > 64 {
		return false
	}
	for _, r := range fragment {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// credentialPrefixes are issuer prefixes used by common access-token formats.
// No legitimate git tag, branch, or commit begins with one.
// Matching is case-sensitive: issuers fix the casing of their prefixes, and
// folding case is what made ordinary words collide ("asia-packages" is not an
// AWS key, but lowercased it matched "ASIA"). Generic prefixes that also occur
// in real path segments (a bare "sk-") are narrowed to their issuer-specific
// forms; secrets with no recognizable prefix are handled by the opaque-shape
// check below.
var credentialPrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", // GitHub
	"glpat-", "gldt-", // GitLab
	"npm_",                                      // npm
	"pypi-",                                     // PyPI
	"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", // Slack
	"sk_live_", "pk_live_", // Stripe
	"sk-proj-", "sk-ant-", // OpenAI, Anthropic
	"AKIA", "ASIA", // AWS access key ids
	"AIza",               // Google
	"hf_",                // Hugging Face
	"dop_v1_", "doo_v1_", // DigitalOcean
	"shpat_", "shpss_", // Shopify
}

// credentialBodyMinimum is how many token characters must follow an issuer
// prefix before the value is treated as a real secret. A bare "ghp_" is a
// prefix, not a credential, and rejecting it would discard ordinary URLs.
const credentialBodyMinimum = 8

// containsCredential reports whether text contains a recognizable access token
// at a token boundary.
//
// This scans rather than splitting on delimiters. Splitting needs the exact
// delimiter set for every position a token might sit in, and each missing
// separator is a silent gap; a boundary-aware scan has no such gaps and is the
// same check wherever it is applied — path, host, or query.
//
// The boundary requirement is what keeps it from firing on ordinary text: the
// prefix must start the value or follow a non-token character, so "task-runner"
// does not match the "sk-" prefix.
func containsCredential(text string) bool {
	for _, prefix := range credentialPrefixes {
		for offset := 0; ; {
			idx := strings.Index(text[offset:], prefix)
			if idx < 0 {
				break
			}
			at := offset + idx
			offset = at + 1

			if at > 0 && isTokenRune(rune(text[at-1])) {
				continue // mid-word, not a token boundary
			}
			body := 0
			for _, r := range text[at+len(prefix):] {
				if !isTokenRune(r) {
					break
				}
				body++
			}
			if body >= credentialBodyMinimum {
				return true
			}
		}
	}
	return false
}

// hasOpaqueSecretRun reports whether text contains a maximal token run shaped
// like an opaque credential with no recognizable issuer prefix — a JWT
// segment, an entitlement token embedded in a download path, or similar.
//
// The prefix list cannot be complete, and origin metadata is optional, so an
// unrecognizable-but-secret-shaped run is dropped rather than published. The
// shape is deliberately narrow to keep legitimate values: a run must be long
// and mix all three character classes (upper, lower, digit), which package
// names (lowercase), version strings (short runs), and content hashes
// (single-case hex) never produce. A bespoke all-lowercase secret still
// passes; omission-preferred is a mitigation, not a guarantee.
func hasOpaqueSecretRun(text string) bool {
	for _, run := range strings.FieldsFunc(text, func(r rune) bool {
		return !isTokenRune(r)
	}) {
		if len(run) < 16 {
			continue
		}
		var hasUpper, hasLower, hasDigit bool
		for _, r := range run {
			switch {
			case r >= 'A' && r <= 'Z':
				hasUpper = true
			case r >= 'a' && r <= 'z':
				hasLower = true
			case r >= '0' && r <= '9':
				hasDigit = true
			}
		}
		if hasUpper && hasLower && hasDigit {
			return true
		}
	}
	return false
}

// isTokenRune reports whether a rune can appear inside an access token.
func isTokenRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '_', r == '-':
		return true
	}
	return false
}

// looksLikeCredential reports whether a value carries a recognizable
// access-token prefix.
//
// A revision reaches an SBOM verbatim after the "@", and unlike a URL fragment
// it cannot simply be required to be hex: tags and branches are legitimate
// here, and they use the same character set a token does. Matching known
// issuer prefixes is therefore the check available, and it is deliberately
// narrow — a bespoke or unrecognized secret format would still pass. The
// stronger guarantee lives on the fragment path, which requires bare hex.
func looksLikeCredential(value string) bool {
	return containsCredential(strings.TrimSpace(value))
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
	// A revision is republished after the "@", so it needs both gates: the
	// issuer-prefix scan and the opaque-shape check. A Pipenv or Poetry ref
	// carrying an entitlement-style token has no recognizable prefix but is
	// exactly the shape hasOpaqueSecretRun rejects. The cost of a false
	// positive is an unpinned repository, which is the safe direction.
	if looksLikeCredential(revision) || hasOpaqueSecretRun(revision) {
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
		if err != nil || parsed.User != nil || parsed.Hostname() == "" {
			return ""
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return ""
		}
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https":
			// The scheme-less branch below requires an owner/repo path;
			// an absolute URL has to clear the same bar or it names no
			// repository at all.
			if strings.Trim(parsed.Path, "/") == "" || hasCredentialPath(parsed) || hasCredentialHost(parsed) {
				return ""
			}
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
	if err != nil || parsed.Host != host || parsed.User != nil || hasCredentialPath(parsed) || hasCredentialHost(parsed) {
		return ""
	}
	return candidate
}

// splitVCSRevision parses a version-control URL and separates any trailing
// "@<revision>" that is already rendered into its path.
//
// Parsing has to happen first. "@" before the host is userinfo — a credential
// — while "@" after the path is a revision, and the two are only
// distinguishable once the URL is parsed. Splitting on "@" beforehand reads
// "https://ghp_secret@github.com" as host "ghp_secret" with revision
// "github.com", which passes every later check and reconstructs the original
// credential.
//
// ok is false when the URL is unsafe to publish at all.
func splitVCSRevision(raw string) (parsed *url.URL, revision string, ok bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || hasCredentialHost(parsed) {
		return nil, "", false
	}
	// Separate the revision before checking the path. "@" is a path delimiter
	// for the credential scan, so leaving a "@<revision>" suffix in place
	// would reject the whole locator for a bad revision instead of dropping
	// just that revision and keeping the repository.
	// Only the SPDX locator form ".../repo@rev" is split: the "@" must sit
	// inside the final segment (not open one, the way a scoped name like
	// "/@core" does) and the suffix must not span segments. A literal "@" in
	// a repository path such as "/teams/@core/library" is part of the
	// repository, and splitting there would export "/teams" at revision
	// "core/library" — a repository that does not exist.
	if idx := strings.LastIndex(parsed.Path, "@"); idx > 0 &&
		parsed.Path[idx-1] != '/' && !strings.Contains(parsed.Path[idx+1:], "/") {
		revision = parsed.Path[idx+1:]
		clean := *parsed
		clean.Path = parsed.Path[:idx]
		parsed = &clean
	}
	if hasCredentialPath(parsed) {
		return nil, "", false
	}
	return parsed, revision, true
}

// vcsToolPrefixes are the version-control tool prefixes SPDX and CycloneDX
// use ahead of a transport. Assuming every repository reference is Git would
// drop the others outright.
var vcsToolPrefixes = []string{"git+", "svn+", "hg+", "bzr+"}

// splitVCSToolPrefix separates a recognized tool prefix from a locator,
// returning the prefix (with its "+") and the remainder.
func splitVCSToolPrefix(locator string) (prefix, rest string, ok bool) {
	lowered := strings.ToLower(locator)
	for _, candidate := range vcsToolPrefixes {
		if strings.HasPrefix(lowered, candidate) {
			return candidate, locator[len(candidate):], true
		}
	}
	return "", locator, false
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
