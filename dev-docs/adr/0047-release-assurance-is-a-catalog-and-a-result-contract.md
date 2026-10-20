# ADR-0047: Release assurance is a catalog plus a per-check result contract

- **Date:** 2026-10-03
- **Revised:** 2026-10-19
- **Status:** Accepted

## Context

Quality checks were independent workflows whose evidence was a job status,
twice a hand-written step summary. Public claims lived in a separate catalog
with its own checker. Nothing tied a claim to whether its check ran for a
given release, nothing verified the published artifacts, and no release
produced one readable answer to "did this one pass?".

## Decision

- One catalog, `docs/assurance/catalog.json`, declares every check with its
  stage, whether it gates, what it proves and what it does not, plus the
  public evidence claims, each naming the check that backs it.
- One result contract, `bomly.assurance-check/v1`, emitted by every check
  through `internal/assurance/cmd`; shell steps never hand-write that JSON.
- One per-release report, `bomly.assurance-report/v1`, committed under
  `docs/assurance/reports/`, is the only data source for the public page.
- Checks are grouped by when they can still change the outcome:
  prerequisites before a tag exists, pre-release against the draft release,
  post-release against the binaries users download. A check goes in the
  earliest stage that has what it needs.
- A declared check with no result is `missing` and blocks its stage when it
  gates; a result the catalog does not declare fails report generation.
  Silence is never success.
- The catalog stores no checksum of any in-repository file: git addresses a
  file by tag and path, and a stored copy can only fall behind, which it did
  the first time the stage ran. Git inputs are pinned by revision and
  containers by digest, because repository history cannot address those.
- Reports are committed to the default branch because the exhaustive stage
  runs after publication and releases are immutable.
- The framework reads repository files, downloads validators and runs
  released binaries; nothing the binary ships may import it.

## Rejected

Pinning workflow and fixture files by checksum (it proved only that the file
had not changed); attaching reports to the release.

## Consequences

- A stale golden is fixed by an ordinary pull request, since the drift-prone
  checks run before a tag exists.
- The report and index schema versions are a contract with bomly.dev; a
  non-additive change teaches the site first.

Enforced by: the `depguard` rule `assurance-is-not-shipped`;
`TestRepositoryCatalogIsValid`.
