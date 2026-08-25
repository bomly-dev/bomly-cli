# ADR-0019: Finding policy-status resolution belongs inside audit

- **Date:** 2026-07-23
- **Status:** Accepted

Auditors remain responsible for creating complete reference-style findings.
After deduplication and `warn-only` handling, the audit stage may run neutral
`sdk.FindingPolicyResolver` implementations. A resolver receives the finding
and package registry, may return a replacement policy status, and cannot remove
or mutate evidence. When multiple resolvers participate, the least suppressive
decision wins.

The first resolver is the package-specific finding baseline under
`internal/baseline`. Its versioned document keys entries by full PURL, finding
kind, auditor, and advisory aliases or stable rule ID. It intentionally contains
no dependency occurrence or project identity, so a baseline is portable across
projects. Discovery happens during normal target preparation: scan and explain
read the materialized project tree, including repositories cloned through
`--url`, while Git diff independently reads the base and head trees. A detected
baseline is logged with its path, entry count, selection mode, and target kind;
automatic discovery warns and behaves as though no baseline exists when path
inspection finds a symbolic-link `.bomly` directory or baseline file. This
rejects discovered links but cannot prevent another process from replacing a
path between inspection and reading. Explicit baseline paths remain trusted
user-selected inputs and may refer outside the project or through a symbolic
link. Each evaluation logs
findings evaluated and accepted. Output receives ordinary findings whose policy
status may be `suppressed` through `Finding.PolicyStatus` / `policy_status`, and
no baseline-specific output model or pipeline stage exists. Renaming the
earlier finding field is an intentional breaking output-contract change while
the CLI output schema identifier remains `1.0` and the compact MCP schema
remains `mcp/1`. Protocol-v1 decoding still accepts the earlier wire field from
existing external auditor plugins.
