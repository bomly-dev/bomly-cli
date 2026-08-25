# ADR-0002: Scorecard matcher reads precomputed runs, not the library

- **Date:** 2026-05-28
- **Status:** Accepted

The OpenSSF Scorecard matcher (repo `bomly-plugin-scorecard-matcher`) fetches precomputed per-repo scores from `api.scorecard.dev` instead of importing `github.com/ossf/scorecard/v5` and running checks in-process. Three reasons:

1. **Dependency cost.** The Scorecard Go library pulls in k8s, buildkit, containerd, bigquery, go-containerregistry, and osv-scanner transitive deps — roughly 150–250 MB of additional code that would land in every Bomly build, violating the "standard library + existing deps only" non-negotiable.
2. **Credentials.** Running Scorecard live makes 60+ GitHub API calls per repo and is unusable without a `GITHUB_AUTH_TOKEN`. A customer-facing CLI that quietly demands a token would surprise users and complicate CI integration.
3. **Latency.** Live runs take 1–3 minutes per repo. The precomputed API answers in tens of milliseconds and the OSSF refresh cadence (weekly) is acceptable for project-posture data.

The matcher attaches `sdk.PackageScorecard` to packages whose upstream source resolves to a `github.com/{owner}/{repo}` URL, dedupes by repo so a monorepo's many packages share one HTTP call, caches 200 responses for 24h, and caches 404s as a sentinel so unscored repos are not retried within the TTL. Packages whose source repo lives outside github.com (GitLab, internal Git) or only in registry metadata not yet wired into Bomly are skipped silently. A future revision can add a deps.dev project-endpoint fallback for the second case without breaking changes.
