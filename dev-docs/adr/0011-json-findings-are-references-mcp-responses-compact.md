# ADR-0011: JSON findings are references; MCP responses are compact projections

- **Date:** 2026-07-08
- **Status:** Accepted

The `--format json` `findings[]` projection now mirrors `sdk.Finding` exactly: an identity-only package ref (display name, org, version, purl), `vulnerability_id`, and `dependency_refs` — no embedded package object and no flat advisory copies. Advisory data lives once in `packages[]` and consumers join by PURL, the way SARIF always did; text/markdown/TUI renderers were converted to the same join. `DiffResponse` gained a `packages[]` collection (PURL-deduplicated union of base and head registries, head wins) so diff audit findings resolve the same way. Rationale: the embedded copies made findings-heavy scan JSON ~10x larger than the data it contained (issue #245) and let the projection drift from the domain model.

The MCP server does not return the CLI JSON documents at all. Tool results land in an agent's context window and MCP clients truncate large results to errors, so `bomly_scan` / `bomly_diff` / `bomly_explain` return compact projections (`schema_version "mcp/1"`, `internal/mcp/types_compact.go`) built from the pipeline's domain data. MCP projects canonical package remediation suggestions; it does not select actions, versions, or package-manager advice. Groups are ranked KEV → severity → EPSS → fixability and hard-capped with explicit truncation counters. Audit may overlay policy status on matching vulnerability entries but cannot create or change suggestions. `bomly_explain` is the bounded drill-down (full advisory detail for one package); the CLI is the artifact channel for complete documents. The former `bomly_vuln_fix_context` tool was folded into these responses. Shortest dependency paths come from a bounded upward BFS over `Graph.Dependents`, never `CollectPathsTo` (all simple paths is exponential on dense graphs).

MCP tool failures expose only stable categories such as request validation,
target preparation, target resolution, pipeline execution, and plugin
inventory. Raw adapter errors never cross the protocol boundary because they
may contain local paths, command output, URLs, or credentials. The server logs
the tool, category, and unwrapped Go cause type without the arbitrary cause
text. Detailed stage logs remain available at debug verbosity only when the
component that produced the failure emits them independently. Validation
messages intentionally remain generic because otherwise a rejected path, URL,
or other user value could be copied into the protocol response.
