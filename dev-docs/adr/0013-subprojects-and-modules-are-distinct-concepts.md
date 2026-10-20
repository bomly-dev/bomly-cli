# ADR-0013: Subprojects and modules are distinct; detectors emit per-module manifests; discovery prunes natively expanded roots

- **Date:** 2026-07-14
- **Revised:** 2026-10-19 (folds ADR-0012 and the per-module decision of ADR-0014)
- **Status:** Accepted

## Context

A monorepo nests in two ways: directories discovery finds on its own, and
members a package manager resolves under one root (reactor modules,
workspace members). Treating them alike double-counts dependencies when both
are planned and loses structure when neither is.

## Decision

- A **subproject** is an independently discovered directory (its own
  `Subproject`, `RelativePath != "."`). A **module** is a member the package
  manager natively resolves under a root manifest.
- The hierarchy is never stored. Views derive it from each manifest's
  `subproject` and repository-relative `path`: a manifest below its
  subproject directory is a module manifest. Scan JSON gained no field.
- Workspace and reactor detectors emit one `GraphEntry` per module with
  subproject-relative paths, so consolidation stays a select, dedup and
  rebase stage. Shared transitives appear in several entries by design; the
  merged graph and PURL registry deduplicate them, and report counts
  deduplicate by PURL rather than summing entries. A detector that cannot
  produce per-module graphs degrades to one merged root manifest.
- `--recursive` walks the tree through the same planner as a root scan. When
  a package manager whose detector natively expands modules has manifest
  evidence at an ancestor directory, nested subprojects of that manager are
  pruned. The directory itself is never skipped, so a Maven ancestor cannot
  hide a nested `requirements.txt`. `gomod` never prunes: a nested `go.mod`
  is a separate module by Go's own semantics.
- Discovery rules are detector-declared. Ignored directories, marker files
  and the multi-module flag ride the detector descriptor, and discovery
  unions them across the unfiltered registry so `--detectors` never changes
  which directories are walked.

## Rejected

Emitting modules in consolidation (it has no ecosystem knowledge); a stored
hierarchy field; discovery rules hardcoded in the walker.

## Consequences

- Every surface (TUI, text, Markdown, MCP) applies one derivation.
- External detector plugins contribute discovery rules through the same
  descriptor fields, with no protocol change.
