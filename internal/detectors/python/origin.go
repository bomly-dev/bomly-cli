package python

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// Python lockfiles name a package's source explicitly, so each resolver can say
// what it resolved rather than leaving the shape of a URL to be guessed at.
// Index roots (PyPI, a private mirror) and local checkouts assert nothing: they
// describe how the environment was built, not where this package came from.

// setUVOrigin records the origin uv resolved for a package.
func setUVOrigin(node *sdk.DependencyNode, source uvLockSource) {
	switch {
	case strings.TrimSpace(source.Git) != "":
		// uv writes the resolved commit as the URL fragment and the
		// requested ref as a query parameter; uvSourceRevision prefers the
		// former, and the invariant drops both from the repository URL.
		if origin := sdk.RepositoryOrigin(source.Git, uvSourceRevision(source)); origin != nil {
			node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
		}
	case strings.TrimSpace(source.URL) != "":
		if origin := sdk.ArtifactOrigin(source.URL); origin != nil {
			node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
		}
	}
}

// setPoetryOrigin records the origin poetry resolved for a package.
func setPoetryOrigin(node *sdk.DependencyNode, pkg *poetryLockPackage) {
	switch strings.ToLower(strings.TrimSpace(pkg.Source.Type)) {
	case "git":
		// ResolvedReference is the commit poetry locked; Reference is the
		// branch or tag that was asked for.
		if origin := sdk.RepositoryOrigin(pkg.Source.URL, firstNonEmpty(pkg.Source.ResolvedReference, pkg.Source.Reference)); origin != nil {
			node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
		}
	case "url":
		if origin := sdk.ArtifactOrigin(pkg.Source.URL); origin != nil {
			node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
		}
	}
}

// setPipenvOrigin records the origin pipenv resolved for a package.
func setPipenvOrigin(node *sdk.DependencyNode, pkg pipfileLockPackage) {
	switch {
	case strings.TrimSpace(pkg.Git) != "":
		if origin := sdk.RepositoryOrigin(pkg.Git, pkg.Ref); origin != nil {
			node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
		}
	case strings.TrimSpace(pkg.File) != "":
		// "file" holds a remote archive for URL requirements and a local
		// path for file:// ones; the invariant keeps only the former.
		if origin := sdk.ArtifactOrigin(pkg.File); origin != nil {
			node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
		}
	}
}

// setPipInspectOrigin records the origin recorded in an installed package's
// PEP 610 direct_url.json, which pip writes only for packages installed from a
// repository, an archive URL, or a local directory.
func setPipInspectOrigin(node *sdk.DependencyNode, directURL map[string]any) {
	resolved := pipInspectResolvedURL(directURL)
	if resolved == "" {
		return
	}
	if vcsInfo, ok := directURL["vcs_info"].(map[string]any); ok {
		vcs, _ := vcsInfo["vcs"].(string)
		if strings.EqualFold(strings.TrimSpace(vcs), "git") {
			if origin := sdk.RepositoryOrigin(resolved, pipInspectRevision(directURL)); origin != nil {
				node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
			}
		}
		// Mercurial, Subversion, and Bazaar have no locator form here.
		return
	}
	if _, ok := directURL["archive_info"]; ok {
		if origin := sdk.ArtifactOrigin(resolved); origin != nil {
			node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
		}
	}
	// dir_info marks a local directory install.
}
