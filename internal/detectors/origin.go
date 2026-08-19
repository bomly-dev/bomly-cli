package detectors

import (
	"net/url"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// Origin metadata keys. Detectors record where a package came from under these
// keys on sdk.Dependency.Metadata; SBOM export reads them back. The values are
// a transport detail between detection and export, so command output filters
// the shared prefix out rather than publishing it.
const (
	// MetadataKeyOriginPrefix is the common prefix of every origin key.
	MetadataKeyOriginPrefix = "bomly.origin."
	// MetadataKeyOriginArtifactURL holds the exact artifact a package was
	// resolved from (a tarball, wheel, gem, crate, ...).
	MetadataKeyOriginArtifactURL = MetadataKeyOriginPrefix + "artifact_url"
	// MetadataKeyOriginVCSURL holds the source repository a package was
	// resolved from.
	MetadataKeyOriginVCSURL = MetadataKeyOriginPrefix + "vcs_url"
	// MetadataKeyOriginVCSRevision holds the resolved revision (commit, tag)
	// pinned alongside MetadataKeyOriginVCSURL.
	MetadataKeyOriginVCSRevision = MetadataKeyOriginPrefix + "vcs_revision"
)

// maxOriginRevisionLength bounds a recorded revision. Real commit hashes and
// tags are far shorter; anything longer is not a revision.
const maxOriginRevisionLength = 128

// Origin is where a package came from, as asserted by the detector that
// resolved it. At most one location is set: a package is either downloaded as
// an artifact or checked out from a repository. An empty Origin means the
// detector had nothing publishable to say, which is the normal case for
// registry-resolved packages whose lockfile records only an index root.
type Origin struct {
	// ArtifactURL is the exact file the package was downloaded from.
	ArtifactURL string
	// VCSURL is the source repository the package was resolved from.
	VCSURL string
	// VCSRevision is the revision pinned in VCSURL, when the lockfile
	// recorded one. Never set without VCSURL.
	VCSRevision string
}

// Empty reports whether no location is set.
func (o Origin) Empty() bool {
	return o.ArtifactURL == "" && o.VCSURL == ""
}

// NormalizeOriginURL is the single invariant every published origin URL must
// satisfy. It is applied when a detector records a URL and again when export
// reads one back, so a plugin-supplied or hand-built graph is held to the same
// rule as a built-in detector.
//
// A value passes only when it is an absolute http or https URL with a host and
// no embedded credentials; the result is always re-serialized from the parse,
// never the caller's raw string. Everything else — local paths, file://,
// git@host:org/repo, ssh://, git+ssh://, and URLs carrying userinfo — is
// rejected, so filesystem layout and credentials cannot reach an SBOM.
//
// Both forms require a non-empty path, so a bare host -- a registry or index
// root -- is never published.
//
// The vcs argument selects the repository form: query and fragment are dropped,
// because they carry the requested ref rather than the resolved one, which
// callers pass separately. The artifact form instead drops the fragment (a
// checksum or anchor, never part of the location) and rejects a value carrying
// a query, which marks a signed or tokenized link rather than a stable
// location.
func NormalizeOriginURL(raw string, vcs bool) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return "", false
	}
	// Hostname also rejects a malformed host such as "https://:8080/pkg".
	if parsed.Hostname() == "" || parsed.User != nil {
		return "", false
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Fragment = ""
	parsed.RawFragment = ""
	// A host root names a server, not a package: it is a registry or index
	// root on the artifact side and no repository at all on the VCS side.
	// An empty path would also make the SPDX "@<revision>" suffix re-parse
	// as userinfo.
	if strings.Trim(parsed.Path, "/") == "" {
		return "", false
	}
	if vcs {
		parsed.RawQuery = ""
		parsed.ForceQuery = false
	} else if parsed.RawQuery != "" || parsed.ForceQuery {
		return "", false
	}
	normalized := parsed.String()
	if normalized == "" {
		return "", false
	}
	return normalized, true
}

// SetOriginArtifact records the exact artifact dep was resolved from, replacing
// any origin already recorded. Callers pass the lockfile field verbatim; values
// that are not publishable URLs are dropped silently, since a missing origin is
// correct output and a wrong one is not. No-op when dep is nil.
func SetOriginArtifact(dep *sdk.Dependency, rawURL string) {
	if dep == nil {
		return
	}
	normalized, ok := NormalizeOriginURL(rawURL, false)
	if !ok {
		return
	}
	clearOrigin(dep)
	setOriginValue(dep, MetadataKeyOriginArtifactURL, normalized)
}

// SetOriginVCS records the source repository dep was resolved from, plus the
// revision the lockfile pinned, replacing any origin already recorded. An
// unpublishable URL drops the whole origin; an unusable revision drops only the
// revision, keeping the repository. No-op when dep is nil.
func SetOriginVCS(dep *sdk.Dependency, rawURL, revision string) {
	if dep == nil {
		return
	}
	normalized, ok := NormalizeOriginURL(rawURL, true)
	if !ok {
		return
	}
	clearOrigin(dep)
	setOriginValue(dep, MetadataKeyOriginVCSURL, normalized)
	if pinned := strings.TrimSpace(revision); isValidOriginRevision(pinned) {
		setOriginValue(dep, MetadataKeyOriginVCSRevision, pinned)
	}
}

// OriginFrom reads the origin a detector recorded on metadata, re-validating
// every value. Anything that fails the invariant is dropped, so export cannot
// publish a location no detector could legitimately have produced. An artifact
// wins over a repository in the case — which the setters never produce — where
// metadata carries both.
func OriginFrom(metadata map[string]any) Origin {
	if len(metadata) == 0 {
		return Origin{}
	}
	if artifact, ok := NormalizeOriginURL(originString(metadata, MetadataKeyOriginArtifactURL), false); ok {
		return Origin{ArtifactURL: artifact}
	}
	repository, ok := NormalizeOriginURL(originString(metadata, MetadataKeyOriginVCSURL), true)
	if !ok {
		return Origin{}
	}
	origin := Origin{VCSURL: repository}
	if pinned := strings.TrimSpace(originString(metadata, MetadataKeyOriginVCSRevision)); isValidOriginRevision(pinned) {
		origin.VCSRevision = pinned
	}
	return origin
}

// isValidOriginRevision reports whether revision is safe to publish beside a
// repository URL. The charset keeps commit hashes, tags, and branch-style refs
// while excluding whitespace, "@", and percent escapes, which would break the
// SPDX "git+<url>@<revision>" locator grammar.
func isValidOriginRevision(revision string) bool {
	if revision == "" || len(revision) > maxOriginRevisionLength {
		return false
	}
	for _, r := range revision {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-', r == '+', r == '/':
		default:
			return false
		}
	}
	return true
}

// clearOrigin drops any origin already recorded on dep, so a later assertion
// replaces an earlier one rather than merging with it: a package has one
// origin, and a stale revision left beside a new repository would name a commit
// that repository may not contain. Only a value that passed the invariant
// clears the previous one, so a rejected input leaves an earlier origin intact.
func clearOrigin(dep *sdk.Dependency) {
	if dep.Metadata == nil {
		return
	}
	delete(dep.Metadata, MetadataKeyOriginArtifactURL)
	delete(dep.Metadata, MetadataKeyOriginVCSURL)
	delete(dep.Metadata, MetadataKeyOriginVCSRevision)
}

// setOriginValue stores one origin fact, allocating the metadata map on demand.
func setOriginValue(dep *sdk.Dependency, key, value string) {
	if dep.Metadata == nil {
		dep.Metadata = make(map[string]any, 1)
	}
	dep.Metadata[key] = value
}

// originString reads a string-valued metadata entry, tolerating a map built by
// something other than the setters.
func originString(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return value
}
