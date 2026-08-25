# ADR-0034: Decisions are recorded as individual ADRs

- **Date:** 2026-08-24
- **Status:** Accepted

## Context

`dev-docs/ARCHITECTURE.md` accumulated 33 inline `### Decision:` entries —
more than half of the document. The entries had no IDs, dates, or status,
could not be linked individually, and crowded out the architecture narrative
they were meant to support.

## Decision

Architecture decisions live as individual architecture decision records in
`dev-docs/adr/`, one file per decision, numbered chronologically by the date
the decision was first recorded. Each file carries an ID, a date, and a
status (`Proposed`, `Accepted`, or `Superseded by ADR-NNNN`).
[`README.md`](README.md) is the index; new decisions copy
[`TEMPLATE.md`](TEMPLATE.md) and take the next number.

The 33 pre-existing decisions were migrated with their prose preserved
verbatim; their dates were backfilled from the git history of the heading
that introduced each one. Migrated entries keep their original free-form
bodies rather than being rewritten into the template's
Context/Decision/Consequences sections. `dev-docs/ARCHITECTURE.md` remains
the architecture narrative and points here.

## Consequences

Decisions are individually linkable and carry provenance. A decision is
revised by superseding it with a new ADR, not by silently editing the old
one (typo and clarity fixes are fine). The index table in `README.md` must
gain a row whenever an ADR is added.
