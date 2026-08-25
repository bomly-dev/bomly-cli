# ADR-0013: Subprojects and modules are distinct concepts, derived in views

- **Date:** 2026-07-14
- **Status:** Accepted

A **subproject** is an independently discovered nested directory (its own discovery-time `sdk.Subproject`, `RelativePath != "."`); a **module** is a member the package manager natively resolves under one root manifest (reactor module, workspace member). The hierarchy is never stored: `output.ClassifyManifest`/`BuildHierarchy` (`internal/output/hierarchy.go`) derive it purely from each manifest's `Subproject` and repo-relative `Path` — a manifest whose directory sits below its subproject directory is a module manifest. Every surface (TUI trees, text report tree, markdown table, MCP compact counts) consumes the same helper, so the JSON schema gained no fields and consumers can apply the identical rule. The scan JSON's per-manifest `subproject` string plus `path` is therefore the single source of truth for project structure.
