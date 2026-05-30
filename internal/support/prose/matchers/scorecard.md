## What `scorecard` does

`scorecard` fetches the latest [OpenSSF Scorecard](https://scorecard.dev) run for every package whose upstream source repository can be resolved to a `github.com/{owner}/{repo}` URL, and attaches the result to the package model.

A Scorecard run rates a project's security-engineering posture: branch protection, dependency-update tooling, signed releases, fuzzing coverage, presence of a SECURITY.md, etc. The matcher does not run the checks itself; it reads precomputed scores published weekly by the OpenSSF at `api.scorecard.dev`, so it is fast, requires no GitHub credentials, and adds no heavy dependencies.

## When it runs

`scorecard` is **opt-in**. It does not run under bare `--enrich`. Select it explicitly:

```bash
bomly scan --enrich --matchers +scorecard
```

This avoids surprising users with extra latency (one HTTP call per unique repository) and keeps the default enrichment surface stable.

## Repository resolution

For each package, the matcher resolves a github.com source repo in this order:

1. PURL `repository_url` / `vcs_url` / `download_url` qualifier
2. PURL of type `github` (`pkg:github/{owner}/{repo}@...`)
3. PURL of type `golang` whose module path begins with `github.com/`
4. The package's `resolvedUrl` if it points at github.com (common for npm tarballs)

Packages with no resolvable github.com source — and packages whose source is hosted elsewhere (GitLab, Bitbucket, internal Git) — are skipped silently. Multiple packages that share a single source repo (e.g. monorepos) are deduplicated; the repo is fetched once and the result is attached to every package that maps to it.

## Network

| Endpoint | Used for | Cache TTL |
| --- | --- | --- |
| `api.scorecard.dev/projects/{host}/{owner}/{repo}` | Per-repo Scorecard run | 24h |

Cache directory (Unix/macOS): `~/.bomly/cache/scorecard/`. Cache failures are logged at WARN and never abort the scan. Repositories the OSSF has not scored return HTTP 404; the matcher records a `notScored` sentinel for the TTL so unscored repos are not retried on every run.

## Output fields

When attached, `package.scorecard` holds:

- `source` — `"api.scorecard.dev"`
- `repository` — `"github.com/{owner}/{repo}"`
- `commitSha` — the commit Scorecard scored
- `scorecardVersion` — Scorecard tool version that produced the run
- `runDate` — ISO timestamp of the run
- `aggregateScore` — overall score, `0.0`–`10.0` (a negative value means inconclusive)
- `checks[]` — one entry per check with `name`, `score`, `reason`, `documentation` link

The text report adds a `Project Posture` section listing each unique repo with its score, run date, Scorecard version, and the number of packages it covers.

## Examples

### Annotate a scan with project posture

```bash
bomly scan --enrich --matchers +scorecard --json | jq '.graph.packages[] | select(.scorecard) | {name, score: .scorecard.aggregateScore}'
```

### Inspect why a single package scored as it did

`bomly explain` does not yet surface scorecard data; for now read the JSON output or visit the canonical UI at `https://scorecard.dev/viewer/?uri=github.com/{owner}/{repo}`.

## Limitations

- **github.com only.** Projects hosted on GitLab, Bitbucket, Codeberg, or internal Git servers will be skipped.
- **Sparse coverage for niche projects.** The OSSF runs Scorecard on a large but not exhaustive set of repositories. Less popular dependencies will return 404.
- **Weekly refresh, not on-demand.** `aggregateScore` and per-check scores reflect the most recent OSSF run, not real-time state.
- **No deps.dev fallback (yet).** Packages whose source repo only lives in registry metadata (npm `repository` field, PyPI `Home-page`, Maven SCM) will be skipped until a future revision wires the deps.dev project endpoint in.
- **Signal-only.** Scorecard data is not yet evaluated by the policy auditor; there is no `--fail-on scorecard<N` gate.
