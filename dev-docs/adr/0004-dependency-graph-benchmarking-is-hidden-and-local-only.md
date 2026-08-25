# ADR-0004: Dependency graph benchmarking is hidden and local-only

- **Date:** 2026-05-31
- **Status:** Accepted

`bomly benchmark` is a hidden maintainer command backed by `internal/benchmark`. It scans public GitHub repositories with native detectors, compares the filtered dependency graph against GitHub Dependency Graph and external Syft SBOMs, and writes deterministic artifacts under `.benchmark-runs/latest`. Bomly scan and SBOM diff execution run in-process through the engine and output model; only the external `git` and `syft` tools remain subprocesses. The in-process adapter builds a native-only registry directly so local configuration and managed-plugin discovery cannot distort benchmark results.

The benchmark reports two distinct signals. Raw agreement is the symmetric overlap with every source. Correctness is computed only for evidence sources and excludes reviewable graph extensions: project/non-registry occurrences classified by the native graph and exact target-manifest edges with mandatory evidence text. Observational sources such as Syft remain visible without being promoted to ground truth. `mismatches.json` retains every source-only, Bomly-only, version-mismatched, and adjudicated item, so an extension can never disappear behind the score. Unadjudicated extra data remains a correctness failure. Package and relationship scores are engineering signals, not claims that a baseline is ground truth. The benchmark is intentionally local-only so exploratory scoring does not become a release or merge gate before it is calibrated.
