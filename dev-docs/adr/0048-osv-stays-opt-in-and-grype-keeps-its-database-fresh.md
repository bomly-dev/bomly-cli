# ADR-0048: OSV stays opt-in; Grype keeps its database fresh

- **Date:** 2026-10-19
- **Status:** Accepted

## Context

`--enrich` runs the matchers the build composition marks default-enabled
(`internal/composition`): `grype` for vulnerabilities and
`depsdev-license-matcher` for licenses. `osv` and `scorecard` are opt-in.
That has been the code's behavior since PR #130 (June 2026), but the user
documentation never followed: `docs/matchers/grype.md` said both `osv` and
`grype` were in the default set, `docs/NETWORK.md`, `docs/MATCHERS.md`,
`docs/GETTING_STARTED.md`, and the README all listed OSV and the CISA KEV
catalog as `--enrich` traffic, and the generated matcher pages took their
"runs by default" cell from a hand-kept list in `internal/support`. No test
could see the drift, so it lasted four months.

bomly-dev/bomly-cli#510 is what it cost. A plain `--enrich --json` scan of
the npm fixture reported 40 of the 57 advisories OSV knows; every missing one
had been published after the Grype database on that machine was built, and
nothing in the output said so. The pinned `bomly-plugin-grype-matcher`
downloaded its database once and never asked Grype for a newer one again: it
passed `update=true` only when the database directory was missing and turned
Grype's age validation off, so an enriched scan answered from a four-month-old
snapshot, silently. The reporter read the output as OSV having failed; OSV
had not run, which is by design, and the docs said otherwise.

Two fixes were on the table. Putting OSV back into the default set would have
given every enriched run a live advisory source at the cost of two network
sources per run and a change to what users get from `--enrich` without
asking. Keeping Grype current fixes the measured defect where it is: the
default source stays one source, and that source stops going stale.

## Decision

The default matcher set does not change: `--enrich` runs `grype` and
`depsdev-license-matcher`; `osv` and `scorecard` join with `--matchers +osv`
and `--matchers +scorecard`. Every document that described a different
default is corrected, and the generated matcher guide now states the default
set from the composition (`matcherDefaultSetMarkdown`) while each matcher
page's "In the default `--enrich` set" cell reads the composition flag
(`matcherRunsByDefault`), so the docs cannot again describe a set the binary
does not run.

The Grype matcher keeps its database fresh. `bomly-plugin-grype-matcher`
drives Grype's own curator: with no database it downloads one; with one
present it asks the distribution service for a newer build at most once per
update-check interval (Grype's default of two hours) and installs it when
there is one. A failed check is a warning, and the local copy still matches.
Once that copy is older than a limit (Grype's default of five days) the
matcher says so at WARN, which Bomly shows without `-v`, because every
advisory published since is missing from that run. Three settings control
this: `db_auto_update`, `db_max_age`, and `db_update_check_interval` in the
plugin's managed configuration, and the same three under `matchers.grype.*`
in the CLI once the pin is bumped to the release that carries them.

An enriched run also logs at INFO which registered matchers it selected and
which it left out (`logMatcherSelection` in `internal/cli/opts`), so `-v`
answers "did OSV run?" without reading the report.

## Consequences

- Once the refreshed plugin is pinned, a plain `--enrich` run contacts
  Grype's database service not only on first use but also, at most every two
  hours, to check for a newer database; the network documentation changes
  with that pin bump, and until then says "on first use", which is what the
  pinned version does. Users who pin a database, or run without network
  access, will set `db_auto_update: false` and accept the staleness warning.
- The CLI consumes the plugin as a pinned module, so the refresh lands in two
  steps: the plugin release first, then a CLI change that bumps the pin and
  exposes the `matchers.grype.*` keys. Until then the full binary keeps the
  database it downloaded first, and `docs/matchers/grype.md` says that
  plainly.
- Still open: a typed warning for a matcher that did not run or served
  expired data is bomly-dev/bomly-cli#340; a "fresh advisory" case in the
  accuracy benchmark is tracked in bomly-planning.
- `TestEntriesShapeAndDefaults` (composition), the registry default tests,
  and the generated-docs drift check pin the default set and the docs that
  describe it.
