# ADR-0048: OSV stays opt-in; Grype keeps its database fresh

- **Date:** 2026-10-19
- **Status:** Accepted

## Context

`--enrich` runs the matchers the build composition marks default-enabled:
Grype for vulnerabilities and deps.dev for licenses; OSV and Scorecard are
opt-in. The user documentation said otherwise for four months, fed by a
hand-kept list. Meanwhile the Grype matcher downloaded its database once and
never refreshed it, so an enriched scan silently answered from a months-old
snapshot and missed advisories OSV knew.

## Decision

- The default set does not change: `--enrich` runs `grype` and
  `depsdev-license-matcher`; `osv` and `scorecard` join with
  `--matchers +osv` and `+scorecard`. Documentation renders the default set
  and each matcher's "runs by default" cell from the composition, so the docs
  cannot describe a set the binary does not run.
- The Grype matcher drives Grype's own curator: it downloads a database when
  none exists, checks for a newer build at most once per update-check
  interval (Grype's default), installs it when there is one, and warns at
  WARN, visible without `-v`, once the local copy exceeds the maximum age. A
  failed check is a warning and the local copy still matches.
  `db_auto_update`, `db_max_age` and `db_update_check_interval` are
  configurable under `matchers.grype.*` and in the plugin's managed
  configuration.
- An enriched run logs at INFO which matchers it selected and left out.

## Rejected

Putting OSV back in the default set: it adds a second network source to
every enriched run and changes what users get from `--enrich` without
asking, while the measured defect was Grype's staleness.

## Consequences

- A plain `--enrich` run may contact Grype's database service on any run,
  not only the first; `docs/NETWORK.md` says so. Users who pin a database set
  `db_auto_update: false` and accept the staleness warning.
- `matchers.grype.db_auto_update` is a string, not a bool: the config loader
  applies `default` tags to a false bool, so a bool defaulting to true could
  never be switched off.
- A typed warning for a matcher that did not run or served expired data is
  still open.

Enforced by: `TestEntriesShapeAndDefaults` in `internal/composition`; the
generated-docs drift check.
