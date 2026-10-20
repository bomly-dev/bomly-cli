# ADR-0024: Detection degrades loudly through one typed warning channel

- **Date:** 2026-07-26
- **Revised:** 2026-10-19 (folds ADR-0009)
- **Status:** Accepted

## Context

A build-tool primary detector falling back to a lockfile parser or Syft
loses transitive resolution, the capability the primary exists for. A
lockfile written by a different manager version than the project pins fails
CI without being a vulnerability. Both were once Debug-only log lines, and
detection had grown three warning paths reaching different surfaces with
different fidelity.

## Decision

- A fallback after a real primary failure (not ready, applicability error,
  install or resolve error, empty graph) is first-class provenance:
  `FallbackFrom` and `FallbackReason` on the detection result, a
  `resolution.fallback` object in scan JSON, and a warning. Designed
  hand-off, where `Applicable()` is false with no error, stays silent. In
  chained fallbacks the outermost real failure is reported.
- Every detector warning is one type, `DetectorWarning{Type, Code, Source,
  Subproject, Manifest, Message}`, collected into
  `PipelineResult.DetectorWarnings`. `Type` carries the meaning and policy
  branches on it: `resolution-failure` and `fallback` mean the graph may be
  incomplete; `package-manager` means the graph is sound and the project's
  configuration is not. `DegradesCoverage` is the one predicate.
- One list feeds every surface: the `warnings` collection of scan, diff and
  explain JSON, the text and Markdown reports, progress children, `-v` logs
  and MCP diagnostics. Progress alone is not enough because `-q` silences it
  and CI has no TTY.
- Package-manager checks compare committed files only and never run
  `pnpm --version`: Corepack shims download managers on demand, which would
  make a plain scan contact a registry without `--enrich`. Combinations no
  manager documents stay silent.
- Warning text embeds values read from the repository, so rendering strips
  control and escape sequences before styling.

## Rejected

Reporting through `Ready`: its verdict is binary and a non-nil error routes
to fallback, demoting a good parser over an advisory. A separate CI-readiness
pipeline stage: it duplicated detector knowledge and re-derived the working
directory.

## Consequences

- A manager mismatch does not block recording a baseline; a failed chain
  does.
- Subprocess stderr is streamed only at `-vv`, may contain secrets the tool
  printed, and is never stored in results.
