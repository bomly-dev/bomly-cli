package python

import (
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

// Python lockfiles name a package's source explicitly, so each resolver can say
// what it resolved rather than leaving the shape of a URL to be guessed at.
// Index roots (PyPI, a private mirror) and local checkouts assert nothing: they
// describe how the environment was built, not where this package came from.

// setUVOrigin records the origin uv resolved for a package.
func setUVOrigin(node *sdk.Dependency, source uvLockSource) {
	switch {
	case strings.TrimSpace(source.Git) != "":
		// uv writes the resolved commit as the URL fragment and the
		// requested ref as a query parameter; uvSourceRevision prefers the
		// former, and the invariant drops both from the repository URL.
		detectors.SetOriginVCS(node, source.Git, uvSourceRevision(source))
	case strings.TrimSpace(source.URL) != "":
		detectors.SetOriginArtifact(node, source.URL)
	}
}

// setPoetryOrigin records the origin poetry resolved for a package.
func setPoetryOrigin(node *sdk.Dependency, pkg *poetryLockPackage) {
	switch strings.ToLower(strings.TrimSpace(pkg.Source.Type)) {
	case "git":
		// ResolvedReference is the commit poetry locked; Reference is the
		// branch or tag that was asked for.
		detectors.SetOriginVCS(node, pkg.Source.URL, firstNonEmpty(pkg.Source.ResolvedReference, pkg.Source.Reference))
	case "url":
		detectors.SetOriginArtifact(node, pkg.Source.URL)
	}
}

// setPipenvOrigin records the origin pipenv resolved for a package.
func setPipenvOrigin(node *sdk.Dependency, pkg pipfileLockPackage) {
	switch {
	case strings.TrimSpace(pkg.Git) != "":
		detectors.SetOriginVCS(node, pkg.Git, pkg.Ref)
	case strings.TrimSpace(pkg.File) != "":
		// "file" holds a remote archive for URL requirements and a local
		// path for file:// ones; the invariant keeps only the former.
		detectors.SetOriginArtifact(node, pkg.File)
	}
}

// setPipInspectOrigin records the origin recorded in an installed package's
// PEP 610 direct_url.json, which pip writes only for packages installed from a
// repository, an archive URL, or a local directory.
func setPipInspectOrigin(node *sdk.Dependency, directURL map[string]any) {
	resolved := pipInspectResolvedURL(directURL)
	if resolved == "" {
		return
	}
	if vcsInfo, ok := directURL["vcs_info"].(map[string]any); ok {
		vcs, _ := vcsInfo["vcs"].(string)
		if strings.EqualFold(strings.TrimSpace(vcs), "git") {
			detectors.SetOriginVCS(node, resolved, pipInspectRevision(directURL))
		}
		// Mercurial, Subversion, and Bazaar have no locator form here.
		return
	}
	if _, ok := directURL["archive_info"]; ok {
		detectors.SetOriginArtifact(node, resolved)
	}
	// dir_info marks a local directory install.
}
