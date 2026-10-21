## How `sbom` resolves

`sbom-detector` is a **direct ingest**. It accepts SPDX 2.3 JSON or CycloneDX 1.4 to 1.7 JSON and treats the document as the source of truth for the graph. No command runs, and no other detector chain fires.

| Step | Strategy | Command |
| --- | --- | --- |
| Resolve graph | JSON ingest | None |

The format is detected from the file content. Bomly rejects SBOM files larger than 256 MiB before decoding them. Ingest is a local file read and never uses the network. See [Network and privacy](../../NETWORK.md) for the shared rule.

## Prerequisites

- Pass `--sbom` with `--path` pointing at the file:

```bash
bomly scan --sbom --path ./vendor.spdx.json
```

Without `--sbom`, files matching `*.spdx`, `*.cdx.json`, `bom`, and similar names are still detected by their evidence patterns, but Bomly may also run other detector chains on the surrounding directory. Use `--sbom` to be explicit.

## Examples

### Audit a vendor SBOM

```bash
bomly scan --sbom --path ./vendor.cdx.json \
  --enrich --audit --fail-on high
```

### Convert SPDX to CycloneDX

The scan pipeline is the conversion path. There is no separate `convert` command:

```bash
bomly scan --sbom --path ./in.spdx.json -o cyclonedx=out.cdx.json
```

### Diff two SBOMs

```bash
bomly diff --sbom --base ./v1.0.cdx.json --head ./v1.1.cdx.json
```

## `--install-first`

Not applicable.

## Reachability

Reachability analyzers need source code, which an SBOM does not carry. `--analyze` reports `not_applicable` for SBOM ingest.

## Limitations

- **Relationship detail depends on the source SBOM.** If the producing tool wrote a flat package list with no `DEPENDS_ON` or `dependencies` edges, Bomly's graph is flat too. `bomly explain` cannot show paths that were never recorded.
- **Vendor-specific extensions** (custom properties, non-standard package types) are passed through to the JSON output but not used for policy decisions.
- **SBOM ingest is exclusive.** Combining `--sbom` with `--image` or `--url` is rejected with exit code 4.
- **Other format versions are rejected.** Only SPDX 2.3 JSON and CycloneDX 1.4 to 1.7 JSON are accepted. SPDX 3.0 is planned.
- **Tag-value SPDX and XML CycloneDX** are not ingested.
