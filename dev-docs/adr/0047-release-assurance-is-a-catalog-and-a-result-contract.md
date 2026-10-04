# ADR-0047: Release assurance is a declarative catalog plus a per-check result contract

- **Date:** 2026-10-03
- **Status:** Accepted

## Context

Quality checks were independent workflows whose evidence was a job status and,
in two cases, hand-written markdown in a step summary. Public claims lived in a
separate `test/evidence/cases.json` catalog with its own checker. Nothing tied a
claim to whether its check actually ran for a given release, nothing verified
the published release artifacts at all, and no release produced a single
readable answer to "did this one pass?".

## Decision

Release assurance is built from three pieces:

- one catalog (`docs/assurance/catalog.json`) declaring every check, its stage,
  whether it gates a release, what it proves, and what it does not — plus the
  public claims, each naming the check that backs it;
- one check-result contract (`bomly.assurance-check/v1`) that every check emits
  through `internal/assurance/cmd`, so shell steps never hand-write JSON;
- one report (`bomly.assurance-report/v1`), written per release into
  `docs/assurance/reports/<tag>.json`, which is the only data source for the
  public assurance page.

Checks are grouped by *when they can still change the outcome*: prerequisites
run before a tag exists, pre-release checks run while the release is still a
draft, and the exhaustive assessment runs afterwards against the binaries users
actually download.

## Consequences

- A declared check with no result is reported as `missing` and blocks its stage
  when it is a gate. Silence is never treated as success.
- A result whose id the catalog does not declare fails report generation, so a
  renamed check cannot quietly vanish.
- A stale golden file is fixed by an ordinary pull request, because the checks
  most prone to drift run before a tag exists.
- Workflow files are no longer pinned by checksum in the catalog. Pinning the
  file proved only that the file had not changed; the per-release check result
  proves the workflow ran and what it found. *(The rest of this point is
  superseded; see the amendment below.)* Fixture and expected-result files
  are still checksummed, because a claim about a golden file is only as good as
  that file — and regenerating goldens therefore has to refresh the catalog
  (`catalog-validate --refresh`, wired into `Update Smoke Goldens`).

  > **Amended 2026-10-03:** the catalog no longer stores a checksum for any
  > file in this repository, and `--refresh` is gone. The argument above for
  > workflow files applies to goldens too: git already addresses a file by
  > tag and path, so the stored checksum was a hand-kept copy that could only
  > fall behind. It did, the first time the prerequisites stage ran on `main`
  > — a golden update and the catalog each passed CI separately and failed
  > together, which no earlier check could have caught and a refresh step only
  > covers when the right workflow makes the change. A claim now names its
  > files by path; what is verified is that they exist. Git inputs stay pinned
  > by revision and containers by digest, because this repository's history
  > cannot address those. The report keeps its schema version: no report had
  > been published when the field was removed, so no reader held the old
  > shape. The versions bind from the first published report onward.
- Reports are committed to the default branch rather than attached to the
  release, because the exhaustive stage runs after publication and GitHub
  releases are immutable once published.
- The framework holds capabilities shipped code must never have: it reads
  repository files, downloads validators, and runs released binaries. The
  `depguard` rule `assurance-is-not-shipped` keeps `cmd/bomly` and every
  package under `internal/` — except the framework and `internal/tools` — from
  importing it, and was proven by mutation when it was added (ADR-0044).
- The SBOM interoperability check makes one assertion no validator does: a
  document merged from two sources links both and adopts neither identity
  (ADR-0042). It reads the generated documents with plain JSON decoding rather
  than the SDK codec, because the codec is the thing under test.
- The report and index schema versions are a contract with bomly.dev: adding an
  optional field keeps the version, and anything else has to teach the site the
  new shape first.
