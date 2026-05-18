## Ingest an existing SBOM

Bomly's `sbom-detector` accepts SPDX 2.3 JSON and CycloneDX 1.6 JSON as direct input. Use it to audit a vendor SBOM, re-evaluate an SBOM produced earlier in CI, or convert between formats.

```bash
bomly scan --sbom --path ./vendor.spdx.json
```

The format is auto-detected by content. No detector chains run; the SBOM is the source of truth for the graph.

## Prerequisites

- A valid SPDX 2.3 JSON or CycloneDX 1.6 JSON file. Tag-Value (SPDX) and XML (CycloneDX) are not currently ingested.
- For vulnerability data: if the SBOM already carries `vulnerabilities` (CycloneDX), `--audit` evaluates them directly. To enrich with fresh data from OSV/KEV, add `--enrich`.

## Examples

### Audit a vendor SBOM

```bash
bomly scan --sbom --path ./vendor.cdx.json \
  --enrich --audit --fail-on high
```

This ingests the vendor's SBOM, looks up every package in OSV/KEV, and fails with exit 2 if any package has a high-severity advisory.

### Convert SPDX to CycloneDX

A scan with `--sbom` input and `-o` output performs the conversion:

```bash
bomly scan --sbom --path ./in.spdx.json -o cyclonedx-json=out.cdx.json
```

Bomly does not advertise a one-shot `convert` command; the scan pipeline is the conversion path.

### Diff two SBOMs

```bash
bomly diff --sbom --base ./v1.0.cdx.json --head ./v1.1.cdx.json
```

Output classifies packages as introduced, resolved, persisted, or version-changed. Add `--audit --fail-on high` to fail when v1.1 introduces a new high-severity advisory.

## Limitations

- **Tier-3 reachability is not run on ingested SBOMs.** Reachability analyzers need access to source code; an SBOM-only input cannot satisfy that. `--reachability` produces `not_applicable` for SBOM ingest.
- **Relationship fidelity depends on the source SBOM.** If the SBOM was produced by a tool that emits a flat package list (no `DEPENDS_ON` / `dependencies` edges), Bomly's graph is also flat. `bomly explain` cannot show paths that aren't recorded.
- **Vendor-specific extensions** (custom properties, non-standard package types) are passed through to the JSON output but are not used for policy decisions.
- **SBOM ingest is exclusive** — combining `--sbom` with `--container` or `--url` is rejected with exit 4.
- **Format versions other than SPDX 2.3 and CycloneDX 1.6** are rejected. SPDX 3.0 and CycloneDX 1.5 ingest are tracked for follow-up.
