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
	if locator.Kind != LocatorVCS || revision == "" || strings.Contains(locator.URL, "@") {
		return locator
	}
	return Locator{Kind: LocatorVCS, URL: locator.URL + "@" + revision}
}

// credentialQueryKeys are query parameter names that carry a secret. A
// download URL using one of them must not be published.
var credentialQueryKeys = []string{
	"token", "access_token", "refresh_token", "id_token", "auth",
	"authorization", "apikey", "api_key", "api-key", "key", "secret",
	"client_secret", "client_id", "password", "passwd", "pwd", "pass",
	"credential", "credentials", "session", "sessionid", "session_id",
	"sig", "signature", "hmac", "nonce",
	"x-amz-signature", "x-amz-credential", "x-amz-security-token",
	"x-goog-signature", "goog-signature",
	"se", "sp", "sv", "sr", "sig_", // Azure SAS parameters
	"private_token", "personal_token", "auth_token", "authtoken",
}

// hasCredentialQuery reports whether a URL's query carries something that
// looks like a secret, by parameter name or by value shape.
func hasCredentialQuery(parsed *url.URL) bool {
	if parsed.RawQuery == "" {
		return false
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		// Unparseable query: cannot be inspected, so assume the worst.
		return true
	}
	for key, vals := range values {
		lowered := strings.ToLower(strings.TrimSpace(key))
		for _, candidate := range credentialQueryKeys {
			if lowered == candidate {
				return true
			}
		}
		for _, value := range vals {
			if looksLikeCredential(value) {
				return true
			}
		}
	}
	return false
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
	return classifyURL(raw, source, ecosystem, false)
}

// classifyURL is the shared classifier. allowBenignQuery relaxes the blanket
// query rejection to a credential-shape check, which is appropriate only when
// the source document itself declared the value a download location.
func classifyURL(raw string, source sdk.DependencySource, ecosystem sdk.Ecosystem, allowBenignQuery bool) Locator {
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
	// Detector-derived values stay HTTP-only: nothing asserts what they are,
	// so the narrowest gate is right. A value the source document declared a
	// download location may also use the network transports the external
	// reference gate accepts.
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	case "ftp", "ftps":
		if !allowBenignQuery {
			return Locator{}
		}
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

	// Every VCS form is classified before the query and fragment gate below.
	// normalizeVCS discards both and keeps only a character-checked revision,
	// so it is safe on values the gate would otherwise reject — and a git
	// dependency legitimately pins its revision that way
	// ("https://host/repo.git?rev=<sha>"). Gating first would silently drop
	// those pins.
	if hint == LocatorVCS {
		return normalizeVCS(parsed)
	}
	if hint != LocatorRegistryRoot {
		// Swift package identity is the repository URL, so swiftpm records a
		// repo even for `kind: registry` pins. Without this the extension
		// check below would demote them to registry roots.
		if ecosystem == sdk.EcosystemSwift {
			return normalizeVCS(parsed)
		}
		if source == sdk.DependencySourceGit || strings.HasSuffix(parsed.Path, ".git") {
			return normalizeVCS(parsed)
		}
	}

	// Credentials also travel outside userinfo: signed and private-registry
	// URLs carry them as query parameters or fragments
	// ("...?token=<secret>", "...?X-Amz-Signature=...").
	//
	// For a detector-supplied value there is nothing asserting the URL is a
	// download location, so any query disqualifies it — a benign parameter
	// cannot be told apart from a credential, and omitting is cheap. When the
	// source document itself declared the value a download location, dropping
	// every query would discard a real assertion such as
	// "https://repo.example/download?id=123", so the check narrows to
	// credential-shaped parameters.
	if parsed.RawQuery != "" {
		if !allowBenignQuery || hasCredentialQuery(parsed) {
			return Locator{}
		}
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

	if isConcreteArtifactPath(parsed.Path) {
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
	out := "git+" + base
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
var credentialPrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", // GitHub
	"glpat-", "gldt-", // GitLab
	"npm_",                                      // npm
	"pypi-",                                     // PyPI
	"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", // Slack
	"sk_live_", "pk_live_", "sk-", // Stripe, OpenAI
	"akia", "asia", // AWS access key ids
	"aiza",               // Google
	"hf_",                // Hugging Face
	"dop_v1_", "doo_v1_", // DigitalOcean
	"shpat_", "shpss_", // Shopify
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
	lowered := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range credentialPrefixes {
		if strings.HasPrefix(lowered, prefix) {
			return true
		}
	}
	return false
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
	if looksLikeCredential(revision) {
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
	// git:// is a legitimate transport for a version-control reference, and
	// isPublishableReferenceURL already accepts it; rejecting it here would
	// drop the repository on a CycloneDX round trip. SPDX renders it as
	// "git+git://host/path", which its version-control grammar allows.
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "git":
	default:
		return ""
	}
	return normalizeVCS(parsed).URL
}

// classifyAssertedDownloadLocation classifies a value that its source document
// already declared to be a download location, such as SPDX
// PackageDownloadLocation.
//
// Two guards that suit a detector-supplied value are relaxed here, because
// they would discard an assertion the source document actually made:
// the path-shape heuristic, which would demote an exact endpoint with no
// archive suffix to a registry root, and the blanket query rejection, which
// would drop "https://repo.example/download?id=123" entirely. Queries are
// still rejected when a parameter looks like a credential, and the rest of the
// safety gate — scheme, host, userinfo, fragment — applies unchanged, so local
// paths and secrets are still dropped.
func classifyAssertedDownloadLocation(raw string) Locator {
	locator := classifyURL(raw, "", "", true)
	if locator.Kind == LocatorRegistryRoot {
		locator.Kind = LocatorArtifact
	}
	return locator
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
	if err != nil || parsed.User != nil || parsed.Host == "" {
		return nil, "", false
	}
	if idx := strings.LastIndex(parsed.Path, "@"); idx >= 0 {
		revision = parsed.Path[idx+1:]
		clean := *parsed
		clean.Path = parsed.Path[:idx]
		parsed = &clean
	}
	return parsed, revision, true
}

// validatedVCSLocator checks an already-rendered "git+<transport>://…"
// locator and returns it unchanged when it is safe to republish, or "".
//
// The pinned revision has to be split off and checked explicitly. In
// "git+https://host/org/repo@ghp_abcd1234" the suffix parses as part of the
// URL path, not as userinfo, so the scheme and userinfo checks never see it —
// an earlier version returned that locator unchanged and republished the
// token. An unsafe revision is dropped and the repository kept, matching what
// normalizeVCS does.
func validatedVCSLocator(locator string) string {
	locator = strings.TrimSpace(locator)
	if !strings.HasPrefix(locator, "git+") {
		return ""
	}
	parsed, revision, ok := splitVCSRevision(strings.TrimPrefix(locator, "git+"))
	if !ok {
		return ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "git":
	default:
		return ""
	}
	if hasCredentialQuery(parsed) || parsed.Fragment != "" {
		return ""
	}

	out := "git+" + strings.TrimSuffix(parsed.String(), "/")
	if isSafeRevision(revision) {
		out += "@" + revision
	}
	return out
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
	case "http", "https", "git", "ftp", "ftps":
		// These are source-declared references, so a benign query such as
		// "?version=1" is part of the assertion and only credential-shaped
		// parameters disqualify it. Fragments stay rejected: they carry no
		// meaning for a reference and are a common place to hide a secret.
		return parsed.Host != "" && parsed.Fragment == "" && !hasCredentialQuery(parsed)
	case "mailto", "urn":
		// Opaque identifiers with no host and no filesystem reach. A `bom`
		// reference to "urn:uuid:..." is the common CycloneDX case.
		return parsed.Opaque != "" && parsed.RawQuery == "" && parsed.Fragment == ""
	default:
		// Anything else — notably file:, data:, and javascript: — stays
		// rejected. Denying unknown schemes is the safe default: these values
		// are republished verbatim, and a scheme Bomly cannot reason about
		// may reference the local machine or execute in a consumer.
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
