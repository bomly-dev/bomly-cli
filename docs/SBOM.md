# SBOM formats

This page shows how to write, read, convert, and compare Software Bills of Materials (SBOMs) with Bomly. Read it when someone asks you for an SBOM or hands you one. The field-by-field mapping lives in the [SBOM field reference](SBOM_REFERENCE.md).

Bomly writes SPDX 2.3 and CycloneDX 1.7. It reads SPDX 2.3 and CycloneDX 1.4 through 1.7.

## What an SBOM is

An SBOM is a structured list of every package in a piece of software, with enough detail (versions, licenses, suppliers, hashes) for another tool to make decisions about it. It is your dependency graph as a portable file. You produce it once and use it many times: in pull request checks, as a release artifact, in supplier audits, and in attestation pipelines.

## Which format to pick

| | SPDX 2.3 | CycloneDX 1.7 |
| --- | --- | --- |
| Steward | Linux Foundation | OWASP |
| Main use | Supply chain and license compliance | Component analysis and vulnerability management |
| Bomly write target | `spdx` | `cyclonedx` |
| Encoding Bomly writes | JSON | JSON |
| Vulnerability data | Not in 2.3 | Built in (`vulnerabilities` array) |
| File hashes | Yes | Yes |
| Relationships | `DESCRIBES`, `DEPENDS_ON`, and more | `dependencies` graph |
| Adoption | NTIA reference, ISO/IEC 5962 | OWASP standard, wide scanner support |

Pick SPDX when a regulator or customer asks for it. Pick CycloneDX when a vulnerability scanner will read the file. Producing both costs nothing extra.

## Write an SBOM

Use `--format <format>` to print the SBOM, or `-o <format>=<path>` to write it to a file next to your normal output:

```bash
# Print one format
bomly scan --format spdx

# Write one format to a file
bomly scan -o spdx=sbom.spdx.json

# Write both formats in one scan
bomly scan -o spdx=sbom.spdx.json -o cyclonedx=sbom.cdx.json
```

`-o` is repeatable. When every `-o` names a file and you set no `--format`, Bomly writes the files and prints nothing. The full rules are in [Output formats](OUTPUT_FORMATS.md#additional-output--o). SBOM formats are available on `scan` only.

## License data needs `--enrich`

Most lockfiles do not record licenses. Only npm and pnpm do. For every other ecosystem (Go, Maven, Python, Cargo, and the rest), a plain `bomly scan -o cyclonedx=...` writes components with no license data, and SPDX writes `NOASSERTION`.

Add `--enrich` to fill licenses in from the deps.dev license matcher:

```bash
bomly scan --enrich -o cyclonedx=bom.cdx.json -o spdx=bom.spdx.json
```

This matters for compliance review. SBOM quality checkers report missing license data as an error, and a reviewer cannot tell "no license recorded" from "not looked up". If you are producing an SBOM for someone else, run it with `--enrich`. Enrichment also adds hashes, CPE identifiers, vulnerabilities, and end-of-life data; the [field reference](SBOM_REFERENCE.md#what-enrichment-adds) lists where each lands.

## Producer metadata for regulated consumers

The EU Cyber Resilience Act (CRA) and similar rules expect an SBOM to name its producer and a security contact. Set them once in your config file:

```yaml
sbom:
  manufacturer: "Example Org"                      # CRA Art. 13(15)
  security_contact: "security@example.com"         # CRA Art. 13(6)
  vulnerability_disclosure_url: "https://example.com/security"  # Art. 13(7)
  support_end: "2030-12-31"                        # CRA Art. 13(8)
```

CycloneDX carries these as `metadata.manufacturer`, external references on the primary component, and a `bomly:support_end_date` property. SPDX 2.3 has no fields for most of them, so Bomly writes an `Organization` creator, the supplier on the primary package, and the contacts in the creation-info comment. When `manufacturer` is set it also becomes the supplier of the primary component in both formats. Bomly never invents supplier or contact data: until the `sbom` section is configured, CRA profile checks will report it missing.

## Read an SBOM

Pass an existing SBOM as the scan target. Bomly skips detection and loads the file:

```bash
bomly scan --sbom --path ./vendor.spdx.json
```

Reading an SBOM is fast and offline. Use it to audit a vendor's SBOM against your policy, to re-run policy on an SBOM a previous CI step produced, or to compare SBOMs across releases. The format is detected from the content. Most SBOM producers, including Syft, can write one of the supported formats (for example `syft <target> -o spdx-json`).

Bomly keeps what the source document asserted about each component (supplier, description, homepage, checksums, CPEs, external references) and about itself (identity, name, timestamp, creators), and writes it back out on export. Every value is re-checked on the way in and the way out. Values that cannot be published safely, such as a URL with a credential or a local path, are dropped.

### What Bomly refuses to read

An SBOM is refused when its JSON has more than one possible reading, or when a component cannot be identified:

| Problem | Why it is refused |
| --- | --- |
| A repeated member name in one object | Different JSON readers pick different values, so two tools would read two different packages from one file |
| Bytes that are not valid UTF-8 | Readers substitute characters, so what a consumer sees is not what the file carried |
| An escape with no valid character (`"\ud800"`) | The JSON standard leaves the result undefined |
| A package URL that cannot be made well-formed | Skipping the component would silently drop it and every relationship that names it |

The error names the problem and where it is. Regenerate the document with a producer that writes each member once and every string as Unicode text. Documents with unknown fields, unusual nesting, or many thousands of components read fine. The size limits of the duplicate-name check are in the [field reference](SBOM_REFERENCE.md#strict-ingest-limits).

## Convert between formats

Read one format and write the other:

```bash
bomly scan --sbom --path ./in.spdx.json -o cyclonedx=out.cdx.json
bomly scan --sbom --path ./in.cdx.json  -o spdx=out.spdx.json
```

There is no separate `convert` command. The scan pipeline is the conversion path, so you can add `--enrich` or `--audit` in the same run. Converting a single document keeps that document's identity, so export, read, export reproduces the same bytes within one format. Some fields have no equivalent in the other format; the [conversion limits table](SBOM_REFERENCE.md#preservation-and-conversion-limits) lists what changes.

## Compare two SBOMs

Compare two SBOM files without re-running detectors on either side:

```bash
bomly diff --sbom --base ./v1.0.spdx.json --head ./v1.1.spdx.json
```

Use it for release notes, supplier-update reviews, and CI checks on prebuilt SBOMs. See the [diff command](commands/diff.md).

## Validate before you ship

Before you treat a generated file as a release artifact, validate it with the validator the receiving system requires. Bomly's own tests parse every emitted document back and check that identity and edges survive, but a receiving system can impose profile rules beyond the base format.

## What Bomly writes

Both formats carry the package name, version, and package URL (PURL), the dependency relationships from the detector graph, content hashes when the lockfile records them, licenses normalized to the current SPDX list, where each package came from when the lockfile says, a stable document identity, and a primary component for the scanned project. Reachability results, policy findings, and run diagnostics are report data, not SBOM fields; use JSON output when you need them. The [SBOM field reference](SBOM_REFERENCE.md) has the mapping for every field.

## See also

- [SBOM field reference](SBOM_REFERENCE.md) — how every field is written, read, and converted
- [Scan targets](SCAN_TARGETS.md) — every input Bomly accepts
- [Output formats](OUTPUT_FORMATS.md) — text, JSON, SARIF, and `-o` rules
- [SBOM detector](detectors/sbom/sbom.md) — ingest specifics
