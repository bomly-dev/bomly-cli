package scorecard

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// githubRepoPattern matches an org/repo segment in any github.com URL form
// (https, ssh, scp-like). Anchored at "github.com/" so it tolerates
// surrounding noise (a npm `repository.url`, a go module path with subpaths,
// a maven SCM URL, etc.).
var githubRepoPattern = regexp.MustCompile(`github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)`)

// resolveRepo derives a canonical "github.com/{owner}/{repo}" repo key for
// pkg, or returns "" when no github.com source can be identified. The
// returned key has no trailing ".git", no scheme, and no path beyond
// owner/repo, so it is safe to append to the api.scorecard.dev URL.
//
// Resolution order, cheapest first:
//  1. PURL `repository_url` / `vcs_url` qualifier (set by Syft for some
//     ecosystems).
//  2. PURL of type `golang` — module path is the repo for github.com modules.
//  3. PURL of type `github` — `pkg:github/{owner}/{repo}`.
//  4. PackageResolvedURL — common for npm/pnpm/yarn tarballs hosted on GitHub.
//  5. NPM metadata `repository` link.
//
// Multiple packages frequently resolve to the same repo (a monorepo's npm
// packages all point at one source); the matcher dedupes by the returned
// key before fetching.
func resolveRepo(pkg *sdk.Package) string {
	if pkg == nil {
		return ""
	}

	if repo := repoFromPURL(pkg.PURL); repo != "" {
		return repo
	}
	if repo := extractGithubRepo(pkg.ResolvedURL); repo != "" {
		return repo
	}
	if repo := repoFromMetadata(pkg.Metadata); repo != "" {
		return repo
	}
	return ""
}

func repoFromPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := packageurl.FromString(raw)
	if err != nil {
		return ""
	}
	for _, q := range parsed.Qualifiers {
		switch strings.ToLower(q.Key) {
		case "repository_url", "vcs_url", "download_url":
			if repo := extractGithubRepo(q.Value); repo != "" {
				return repo
			}
		}
	}
	switch strings.ToLower(parsed.Type) {
	case "github":
		// pkg:github/{owner}/{repo}@version
		owner := strings.TrimSpace(parsed.Namespace)
		name := strings.TrimSpace(parsed.Name)
		if owner != "" && name != "" {
			return canonicalRepo(owner, name)
		}
	case "golang":
		// Module path lives in Namespace + "/" + Name. github.com modules
		// always start with "github.com/owner/repo[/subpath…]".
		modulePath := strings.TrimPrefix(strings.TrimSpace(parsed.Namespace)+"/"+strings.TrimSpace(parsed.Name), "/")
		if repo := extractGithubRepo(modulePath); repo != "" {
			return repo
		}
	}
	return ""
}

func repoFromMetadata(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	if npm, ok := meta[sdk.MetadataKeyNPM].(*sdk.NPMPackageMetadata); ok && npm != nil {
		// NPMPackageMetadata does not currently carry a `repository` field;
		// when it does (or when a package.json scrape lands), this is the
		// hook. Kept as an explicit branch so the surface is obvious.
		_ = npm
	}
	return ""
}

// extractGithubRepo finds the first github.com owner/repo pair in raw and
// returns it canonicalized. Returns "" when raw contains no github.com
// reference.
func extractGithubRepo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Strip a leading scheme if present; the regex tolerates either way but
	// stripping clarifies trace logs.
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		if strings.EqualFold(parsed.Host, "github.com") {
			parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
			if len(parts) >= 2 {
				return canonicalRepo(parts[0], parts[1])
			}
		}
	}
	matches := githubRepoPattern.FindStringSubmatch(raw)
	if len(matches) == 3 {
		return canonicalRepo(matches[1], matches[2])
	}
	return ""
}

// canonicalRepo returns "github.com/{owner}/{repo}" with no trailing ".git"
// or surrounding slashes.
func canonicalRepo(owner, repo string) string {
	owner = strings.Trim(owner, "/")
	repo = strings.TrimSuffix(strings.Trim(repo, "/"), ".git")
	if owner == "" || repo == "" {
		return ""
	}
	return path.Join("github.com", owner, repo)
}
