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
- Dependency relationships from the detector graph.
- File-level evidence when the detector provided it.

When `--enrich` is set, components are enriched from the matching-stage package
registry (keyed by PURL):

- Licenses learned during matching (preferred over detection-time licenses).
- Content digests as component hashes (CycloneDX `hashes`, SPDX `checksums`).
- CPEs (CycloneDX `cpe`, SPDX `SECURITY`/`cpe23Type` external references).
- Vulnerabilities — CycloneDX as a first-class `vulnerabilities` array (ratings,
  CWEs, advisories, `affects`); SPDX as `SECURITY`/`advisory` external references.
- End-of-life status (CycloneDX `bomly:eol*` properties, SPDX package comment).

Reachability annotations and other Bomly-specific metadata are emitted in the JSON output (`--json` or `--format json`), not in the standard SBOM formats. See [Output formats](OUTPUT_FORMATS.md).

### Preservation and conversion limits

Bomly preserves component identity (including PURL), dependency edges, roots,
scope, package type, licenses, digests, CPEs, and the enrichment fields described
above when the destination format has an equivalent representation. Encoding is
deterministic when the scan timestamp and document identifiers are fixed.

Some information necessarily becomes less specific during conversion:

- CycloneDX vulnerability records preserve ratings, CWEs, affected component
  references, descriptions, and advisory URLs. SPDX 2.3 represents each
  vulnerability as a package security advisory reference, so ratings, affected
  ranges, fix versions, and descriptions are not carried through an SPDX 2.3
  round trip.
- Development scope maps to CycloneDX `excluded`; runtime scope maps to
  `required`. SPDX stores Bomly's normalized scope in the package comment.
- Bomly relationship confidence (`direct`, `transitive`, or `unknown`), source
  provenance, reachability analysis, policy findings, and run diagnostics are
  report data rather than portable SBOM fields. Use JSON when those distinctions
  must survive export and import.
- A CycloneDX document has one metadata component. When an input graph has
  multiple roots, every root remains in the dependency graph, but only the first
  deterministic root is selected as that metadata component.

Before treating a generated file as a release artifact, validate it with the
standard validator required by the receiving system. Bomly's tests parse every
emitted target back through the corresponding typed codec and exercise
round-trip identity and edge preservation; receiving systems can impose
additional profile rules beyond the base format.

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
