# SBOM Formats

Bomly reads and writes the two open SBOM standards used in production today: SPDX 2.3 and CycloneDX 1.6.

## What's an SBOM?

A Software Bill of Materials is a structured list of every package in a piece of software, with enough metadata (versions, licenses, suppliers, hashes) for an outside tool to make decisions about it. It is the dependency graph as a portable file.

You produce an SBOM once and consume it many times: in PR checks, in release artifacts, in supplier audits, in attestation pipelines.

## Format comparison

| | SPDX 2.3 | CycloneDX 1.6 |
| --- | --- | --- |
| Steward | Linux Foundation | OWASP |
| Primary use case | Software supply chain and license compliance | Component analysis and vulnerability management |
| Bomly write target | `spdx` | `cyclonedx` |
| Encoding | JSON (also Tag-Value and YAML upstream) | JSON (also XML upstream) |
| Vulnerability data | Add-on (SPDX 3.0) | First-class (`vulnerabilities` array) |
| File hashes | Yes | Yes |
| Relationship edges | Rich `DESCRIBES`, `DEPENDS_ON`, etc. | `dependencies` graph |
| Adoption | NTIA reference, ISO/IEC 5962 | OWASP standard, broad scanner support |

In practice: pick **SPDX** when a regulator or customer asks for it; pick **CycloneDX** when a vulnerability scanner is on the other end. Producing both is cheap.

## Writing an SBOM

Use `--format <format>` for the primary stdout output, or `-o <format>[=<path>]` when you want an SBOM alongside another output. The format alone writes to stdout; `format=path` writes to a file:

```bash
# One format to stdout
bomly scan --format spdx

# One format to a file
bomly scan -o spdx=sbom.spdx.json

# Two formats in one scan
bomly scan \
  -o spdx=sbom.spdx.json \
  -o cyclonedx=sbom.cdx.json

# One format to stdout, one to a file
bomly scan -o spdx -o cyclonedx=sbom.cdx.json
```

Constraints:

- At most one `-o` may omit `=<path>`. Two stdout outputs would collide.
- `-o spdx=` (empty path) is an error.
- `--format spdx`, `--format cyclonedx`, `-o spdx`, and `-o cyclonedx` are supported by `scan` only.
- Paths are resolved relative to the current working directory.

## Ingesting an SBOM

Skip detection entirely and load an existing SBOM as input:

```bash
bomly scan --sbom --path ./vendor.spdx.json
```

This is fast, offline, and useful for:

- Auditing a vendor SBOM against your policy.
- Re-running policy on an SBOM you produced in a previous CI step.
- Diffing SBOMs across releases.

Format is auto-detected by content (both SPDX and CycloneDX JSON are supported).

## Diffing SBOMs

Compare two SBOM files without re-running detectors on either side:

```bash
bomly diff --sbom --base ./v1.0.spdx.json --head ./v1.1.spdx.json
```

Useful for release notes, supplier-update reviews, and CI checks on prebuilt SBOMs.

## What Bomly puts in the SBOM

Both formats carry:

- Package name, version, PURL.
- License when a matcher resolved one (`--enrich` required).
- Dependency relationships from the detector graph.
- File-level evidence when the detector provided it.
- Vulnerability annotations in CycloneDX when `--enrich` is set.

Reachability annotations and Bomly-specific metadata are emitted in the JSON output (`--json` or `--format json`), not in the standard SBOM formats. See [Output formats](OUTPUT_FORMATS.md).

## Format conversion

To convert between formats, run a scan and emit both in one pass:

```bash
bomly scan --sbom --path ./in.spdx.json --format cyclonedx > out.cdx.json
```

Bomly does not advertise a one-shot `convert` command — the scan pipeline is the conversion path.

## See also

- [Scan targets](SCAN_TARGETS.md) — every input Bomly accepts
- [Output formats](OUTPUT_FORMATS.md) — text, JSON, SARIF, SBOM details
- [SBOM detector](detectors/ecosystems/sbom/sbom.md) — ingest specifics
