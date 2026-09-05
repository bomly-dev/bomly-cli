package cargo

import (
	"net/url"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// setCargoOrigin records the repository a git-sourced crate was resolved from.
// Cargo writes one source string per package: "registry+"/"sparse+" name an
// index root rather than this crate's location, path and workspace members
// carry no source at all, and only "git+" identifies where the code came from.
func setCargoOrigin(node *sdk.DependencyNode, source string) {
	trimmed := strings.TrimSpace(source)
	if !strings.HasPrefix(trimmed, "git+") {
		return
	}
	repository := strings.TrimPrefix(trimmed, "git+")
	// Origins is a list now (ADR-0041): a node folds every source it was
	// resolved from rather than holding one, and MergeOrigins is the door in.
	if origin := sdk.RepositoryOrigin(repository, cargoSourceRevision(repository)); origin != nil {
		node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
	}
}

// cargoSourceRevision returns the revision cargo locked. The URL fragment holds
// the resolved commit; the "rev", "tag", and "branch" query parameters hold
// what the manifest asked for, which is the weaker answer.
func cargoSourceRevision(repository string) string {
	parsed, err := url.Parse(strings.TrimSpace(repository))
	if err != nil {
		return ""
	}
	if parsed.Fragment != "" {
		return parsed.Fragment
	}
	query := parsed.Query()
	for _, key := range []string{"rev", "tag", "branch"} {
		if value := strings.TrimSpace(query.Get(key)); value != "" {
			return value
		}
	}
	return ""
}
