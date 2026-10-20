# ADR-0034: Decisions are recorded as concise ADRs

- **Date:** 2026-08-24
- **Revised:** 2026-10-19
- **Status:** Accepted

## Context

`dev-docs/ARCHITECTURE.md` once held 33 inline decision entries with no IDs
or dates. Extracting them into one file per decision fixed that and
introduced a new failure: an ADR per change. By October 2026 there were 48,
totalling about 29,000 words. Most recorded how a feature was implemented,
nine carried appended amendment blocks contradicting the body above them,
and a third described one ecosystem, one plugin or one error message, with
no alternative anyone would propose again.

## Decision

An ADR is written only when all three hold: a real alternative exists that a
competent contributor would propose again; reversing the choice later is
expensive (an output or wire contract, a cross-repository boundary, a
security boundary, a public claim); and the reason is not visible from the
code or from a guard's message. Everything else is a code comment, a package
doc comment, or a paragraph in the architecture narrative.

One decision per file, about 300 words and never more than about 400: a
one-paragraph context, the decision as present-tense rules, the rejected
alternative in a sentence, at most five consequences, and the test, lint
rule or analyzer that enforces it. No implementation history, no
per-ecosystem lists, identifiers only where the reader must go.

A decision that changes is revised in place with a `Revised` date; git holds
the history, and amendment blocks are never appended. A reversal is a new
ADR, and the old file becomes a three-line stub pointing at it. A record that
stops being a decision becomes a stub saying where its content lives.
Numbers are never reused.

## Rejected

An ADR per pull request, which produced this cleanup. Deleting retired
files: their numbers are cited from code and lint configuration.

## Consequences

- The 2026-10-19 cleanup reduced 49 records to 21 live ones and 28 stubs;
  `dev-docs/adr/README.md` indexes both.
- `AGENTS.md` carries the bar in two sentences; this file carries the
  reasoning.
