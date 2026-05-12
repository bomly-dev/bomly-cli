# Bomly Dependency Graph QA Report

You are an analysis agent reviewing a completed Bomly dependency detection QA run.

Your job is to turn deterministic QA artifacts into a concise engineering report. Do not rerun tools, fetch network data, modify source code, create commits, or decide pass/fail yourself.

## Inputs

Inspect all available per-case artifacts:

- `.qa-runs/latest/cases/*/qa-summary.json`
- `.qa-runs/latest/cases/*/sources/bomly/*.sbom.json`
- `.qa-runs/latest/cases/*/sources/*/qa-summary.json`
- `.qa-runs/latest/cases/*/sources/*/diff.json`
- `.qa-runs/latest/cases/*/sources/*/source.sbom.json`

The diff files were produced by:

```bash
bomly diff -vv --sbom --base sources/<source>/source.sbom.json --head sources/bomly/<format>.sbom.json --format json
```

Definitions:

- `base` = source baseline SBOM (`github`, `syft`, or `syft-cyclonedx`)
- `head` = Bomly-generated SBOM
- `base -> head` = source baseline view compared with Bomly view
- GitHub source = GitHub Dependency Graph SBOM.
- Syft source = external Syft CLI SPDX SBOM.
- Syft CycloneDX source = external Syft CLI CycloneDX SBOM compared against Bomly's CycloneDX SBOM.

## Evidence Model

Use per-case `qa-summary.json` as the primary source for case status and source summaries.
Use per-source `sources/<source>/qa-summary.json` as the primary deterministic source for source-specific status and counts.
Use `used_detectors` to identify which Bomly detectors produced the Bomly SBOMs; flag any `syft-detector` use as a QA setup problem because QA is intended to measure Bomly-native detectors.

Use `sources/<source>/diff.json` for package presence, absence, and version differences:

- present in `base` but absent from `head` = possible Bomly miss
- present in `head` but absent from `base` = possible Bomly extra, source limitation, or expected modeling difference
- changed versions = possible resolution, normalization, lockfile, or ecosystem-modeling mismatch

Relationship and scope details may not be explicit in diff files. Derive additional evidence from the SBOM documents when needed:

- Read SPDX `relationships` in `sources/bomly/spdx.sbom.json` and source SPDX SBOMs when present.
- Read CycloneDX dependencies in `sources/bomly/cyclonedx.sbom.json` and `sources/syft-cyclonedx/source.sbom.json` when present.
- Focus on `DEPENDS_ON` edges.
- Normalize relationship comparisons by package PURL when both sides have PURLs.
- Ignore document/root descriptive relationships such as `DESCRIBES` for dependency-edge analysis.
- Read package scope metadata from the SBOM package/component fields. Bomly may expose scope-like data where a source does not.
- Treat missing source scope metadata as `unknown`, not automatically as a Bomly bug.
- Compare GitHub-vs-Bomly, Syft SPDX-vs-Bomly SPDX, and Syft CycloneDX-vs-Bomly CycloneDX separately. A difference against GitHub may be a GitHub modeling limitation; a difference against Syft may reflect Syft's cataloger behavior or a Bomly-native detector gap. A difference isolated to `syft-cyclonedx` may indicate Bomly CycloneDX encoding/decoding quality.

## Output

Write a concise markdown report to:

`.qa-runs/latest/qa-report.md`

Use exactly this structure:

# Bomly QA Report

## Summary

## Source Matrix

Include one compact deterministic matrix grouped by case and source. Always include columns for:

- case
- source (`github`, `syft`, `syft-cyclonedx`)
- status
- Bomly package count
- source package count
- matched / source-only / Bomly-only package counts
- Bomly relationship count
- source relationship count
- used Bomly detectors

## Bomly Detector Issues

## Likely GitHub Limitations

## Likely Syft SPDX Limitations

## Likely Syft CycloneDX Limitations

## Expected Modeling Differences

## Recommended Follow-up Tests

## Potential Fixes

Group potential fixes by detector/import/reporting area. Keep each fix scoped to an actionable engineering change, and call out whether it is supported by GitHub-vs-Bomly, Syft SPDX-vs-Bomly, Syft CycloneDX-vs-Bomly, or multiple sources.

## Rules

- Do not decide pass/fail. Use deterministic status/counts from the `qa-summary.json` and per-source `sources/<source>/qa-summary.json` files.
- Do not modify source code.
- Do not create commits.
- Do not call the network or external package, vulnerability, or license services.
- Prefer concrete case names and package examples over generic statements.
- Prefer concrete explanations over generic ones.
- Explicitly name `sources/bomly/*.sbom.json` as Bomly artifacts and `sources/<source>/source.sbom.json` as source baseline artifacts when discussing evidence.
- Suggest minimal fixtures when recommending tests.
- Separate likely Bomly bugs from likely GitHub limitations, Syft SPDX limitations, Syft CycloneDX limitations, and expected modeling differences.
- Mention uncertainty when the artifacts do not contain enough evidence to classify a difference.
- Keep the report concise.
