# ADR-0048: The default enrichment set includes a live advisory source

- **Date:** 2026-10-19
- **Status:** Accepted

## Context

`--enrich` runs the matchers the build composition marks default-enabled
(`internal/composition`). From PR #130 (June 2026) until this decision, the
only default vulnerability matcher was `grype`; `osv` was registered but
opt-in. PR #130 was about plugin examples and never said it changed the
default set, and the documentation kept describing both `osv` and `grype` as
default (`docs/matchers/grype.md`, `docs/NETWORK.md`, `docs/MATCHERS.md`),
so the code and the docs disagreed for four months without a test noticing.

The consequence surfaced as bomly-dev/bomly-cli#510. The pinned Grype module
downloads its vulnerability database once and never checks its age
(`ValidateAge = false`, download only when the directory is missing). On a
machine whose database was built in June, a plain `--enrich --json` scan of
the npm fixture reported 40 of the 57 advisories OSV knows, and every missing
one was published after the database was built. Nothing said so: the report
carried no OSV source, `warnings` was empty, and a run with the OSV cache set
aside took under a second because OSV was never queried. Advisory recall on
the default path was bounded by a local database, silently.

Two things were on the table: refresh the Grype database on a TTL (a change
in `bomly-plugin-grype-matcher`, which this repository consumes as a pinned
module), and put a live source back into the default set here. They are not
alternatives. A refreshed database still answers from a snapshot and still
needs a staleness warning; a live query does not replace Grype's distro
matching for container scans.

## Decision

`osv` is default-enabled alongside `grype`. With `--enrich` and no
`--matchers` selection, Bomly runs `grype`, `osv`, and
`depsdev-license-matcher`; `scorecard` stays opt-in. A plain `--enrich` run
therefore always consults the live OSV feed (through the 24h response cache)
and never depends on a local database alone for the advisories it reports.
Advisories both matchers return are merged by identity in the engine's
consolidation step and reported once.

The generated matcher guide states the default set from the composition
(`matcherDefaultSetMarkdown`), and the per-matcher "runs by default" cell
reads the composition too (`matcherRunsByDefault`), so the docs cannot again
describe a default set the binary does not run. An enriched run logs at INFO
which registered matchers it selected and which it left out
(`logMatcherSelection` in `internal/cli/opts`), so `-v` answers "did OSV
run?" without reading the report.

## Consequences

- Every `--enrich` run now queries `api.osv.dev` and downloads the CISA KEV
  catalog (6h cache). The network and privacy documentation already listed
  both as `--enrich` traffic; the behavior now matches it. Users who want
  Grype alone pass `--matchers -osv`.
- Smoke goldens for cases that enrich without pinning `--matchers` (the four
  reachability scans) gain OSV advisories and must be regenerated with the
  golden workflow.
- Still open, and not addressed here: the Grype database refresh and a
  visible staleness warning belong to `bomly-plugin-grype-matcher`; a typed
  warning for a matcher that did not run or served expired data is
  bomly-dev/bomly-cli#340; a "fresh advisory" case in the accuracy benchmark
  is tracked in bomly-planning.
- `TestEntriesShapeAndDefaults` (composition), the registry default tests,
  and the generated-docs drift check pin the new default set.
