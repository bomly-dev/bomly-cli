# SBOM Formats

Bomly reads and writes the two open SBOM standards used in production today. It writes SPDX 2.3 and CycloneDX 1.7, and ingests SPDX 2.3 plus CycloneDX 1.4 through 1.7.

## What's an SBOM?

A Software Bill of Materials is a structured list of every package in a piece of software, with enough metadata (versions, licenses, suppliers, hashes) for an outside tool to make decisions about it. It is the dependency graph as a portable file.

You produce an SBOM once and consume it many times: in PR checks, in release artifacts, in supplier audits, in attestation pipelines.

## Format comparison

| | SPDX 2.3 | CycloneDX 1.7 |
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
- When every `-o` names a file and `--format` is not set, a successful run writes the files and prints nothing — add `--format text` if you also want the terminal report.
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
- Content hashes captured at detection time, when the ecosystem records them:
  npm/pnpm/yarn/bun lockfile integrity values and Go module `go.sum` tree
  hashes (the `h1:` SHA-256 dirhash, hex-encoded — the same convention
  cyclonedx-gomod uses). Values are normalized to lowercase hex so they are
  schema-valid in both formats.

### Document identity

Every generated document carries a stable identity:

- A generated `urn:uuid` serial number (CycloneDX `serialNumber`; the same
  nonce forms the SPDX document namespace, so the two exports of one scan are
  correlatable).
- The producing tool with its version (CycloneDX `metadata.tools[]`; SPDX
  `Creator: Tool: bomly-cli-<version>`), plus one tool entry per detector that
  contributed to the graph.
- A primary component describing the scanned project. When the dependency
  graph has a single root, that root is the primary component. When a scan
  discovers multiple manifests (several ecosystems, several workflow files),
  Bomly synthesizes a primary component named after the scanned project with a
  `pkg:generic` PURL; it depends on every graph root, so the exported
  dependency graph is connected and both formats agree on the document's
  subject. The synthesized component is not repeated in the CycloneDX
  component inventory, and Bomly skips it when re-ingesting its own SBOMs.

### Provenance metadata (EU CRA readiness)

The optional `sbom` config section embeds producer metadata that regulated
consumers (for example the EU Cyber Resilience Act's SBOM expectations) ask
for:

```yaml
sbom:
  manufacturer: "Example Org"                      # CRA Art. 13(15)
  security_contact: "security@example.com"         # CRA Art. 13(6)
  vulnerability_disclosure_url: "https://example.com/security"  # Art. 13(7)
  support_end: "2030-12-31"                        # CRA Art. 13(8)
```

CycloneDX: `metadata.manufacturer`, `security-contact` / `advisories`
external references on the primary component, and a `bomly:support_end_date`
metadata property. SPDX 2.3 has no first-class fields for most of these, so
Bomly emits an `Organization` creator, the supplier on the primary package,
and the contact fields in the creation-info comment.

Without these fields Bomly's exports satisfy the NTIA minimum elements
(supplier defaults to the producing tool); third-party CRA profile checks
will flag the missing manufacturer/contact metadata until the `sbom` section
is configured. Per-component supplier and description data is not invented:
those fields stay empty unless a data source actually provides them.

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
  multiple roots, every root remains in the dependency graph and the
  synthesized primary component (see "Document identity" above) links them;
  ingest paths that predate the synthesized root treat the first
  deterministic root as the primary component.

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
- [SBOM detector](detectors/sbom/sbom.md) — ingest specifics
