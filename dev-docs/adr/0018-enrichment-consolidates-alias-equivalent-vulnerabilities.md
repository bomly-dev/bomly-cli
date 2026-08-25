# ADR-0018: Enrichment consolidates alias-equivalent vulnerabilities

- **Date:** 2026-07-23
- **Status:** Accepted

Matchers may describe the same package vulnerability under different primary
advisory IDs, even within a single matcher database. After all selected
matchers run, the engine consolidates vulnerability records per PURL using the
transitive closure of `ID` and `Aliases`. The canonical record unions advisory
IDs and evidence, uses the richest input record for scalar metadata, and
retains the highest severity and conservative fix/reachability state. OSV
`Related` IDs never trigger consolidation because
they may identify distinct vulnerabilities. This policy belongs at the central
enrichment boundary so built-in and protocol-v1 external matchers receive the
same behavior without owning global identity policy. Baseline construction
repeats the identity normalization defensively for legacy or independently
constructed registries.
