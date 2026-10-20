# SBOM field reference

This page says exactly how Bomly writes, reads, and converts each part of an SBOM. Read it when you integrate Bomly's SBOMs with another tool, or when a field does not look the way you expected. The how-to is on [SBOM formats](SBOM.md).

## What both formats carry

| Data | Where it comes from | Notes |
| --- | --- | --- |
| Package name, version, PURL | The detector graph | The PURL is the component identity in both formats |
| Dependency relationships | The detector graph | CycloneDX `dependencies`; SPDX `DEPENDS_ON` and `DESCRIBES` |
| File-level evidence | The detector, when it provides it | |
| Content hashes | The lockfile, when the ecosystem records them | npm, pnpm, yarn, and bun integrity values; Go `go.sum` tree hashes (the `h1:` SHA-256 dirhash, hex-encoded, as cyclonedx-gomod writes it); SHA-256 of GitHub Actions workflow and action manifests; the commit ID of SHA-pinned actions. Values are lowercase hex in both formats |
| Licenses | The lockfile, or enrichment | Deprecated identifiers such as `GPL-2.0` are rewritten to their replacements (`GPL-2.0-only`), inside expressions too. See [How licenses are written](#how-licenses-are-written) |
| Package namespace | The PURL | CycloneDX `group`: an npm scope, a Go module owner, a Maven group. SPDX 2.3 has no such field; the namespace stays inside the PURL |
| Package purpose | The graph | SPDX `primaryPackagePurpose`: `LIBRARY` for registry packages, `APPLICATION` for the primary component |
| Fix guidance | Enrichment | CycloneDX vulnerability `recommendation` ("Upgrade <package> to <version>") when a fixed version is known. Nothing is written when no fix is known. SPDX 2.3 has no field for it |
| Package origin | The lockfile | See [Where a package came from](#where-a-package-came-from) |

## How licenses are written

A license value can be an SPDX identifier, a compound expression, or free text. The formats keep these apart, and tools score them differently. Bomly therefore checks each value instead of guessing from its source:

| The value | CycloneDX | SPDX 2.3 `licenseDeclared` |
| --- | --- | --- |
| One SPDX identifier (`MIT`) | `license.id`, spelled canonically | The identifier |
| A compound expression (`MIT OR Apache-2.0`) | `expression` | The expression |
| Anything else (`see LICENSE file`) | `license.name`, as free text | A `LicenseRef-*` identifier, with the text in `hasExtractedLicensingInfos` |
| Nothing | No `licenses` key | `NOASSERTION` |

When a source lists several licenses for one package, it says which licenses it found, not how they relate. Bomly does not fill that gap. CycloneDX lists them as separate entries, which asserts no relationship. SPDX 2.3 has one expression field and no way to list licenses without relating them, so Bomly joins them with `AND`. That overstates obligations rather than understating them. It is the one place the two formats differ on purpose.

When a source does state the relationship, it writes one expression (`Apache-2.0 OR MIT` is how registries record dual licensing), and both formats publish it as given. Bomly never rewrites an `OR` into an `AND`.

SPDX `licenseConcluded` is always `NOASSERTION` for packages Bomly resolved itself. "Concluded" means the license the document's author determined by examining the package. Bomly reports what a lockfile or registry declares and examines no contents, so it has nothing to conclude. An ingested document that concluded a license re-exports it as concluded.

## Where a package came from

Each detector reports a package's origin from the field its own lockfile records it in. Bomly does not infer origin from the shape of a URL, because the same string means different things in different ecosystems. A detector reports one of two things, or nothing:

| What the lockfile records | SPDX 2.3 | CycloneDX |
| --- | --- | --- |
| The exact file the package was fetched from | `downloadLocation` | `distribution` external reference |
| The repository it was resolved from, plus the revision when the manifest names one (a commit, or for GitHub Actions the tag or branch as written) | `downloadLocation` as `git+<url>@<revision>`; `sourceInfo` when an artifact already holds the download location | `vcs` external reference: `git+<url>@<revision>` when a revision is recorded, the plain repository URL otherwise |
| Neither | `NOASSERTION` | No reference |

A pinned repository is written as the same string in both formats, `git+<url>@<revision>`. That is the version-control locator form SPDX 2.3 defines, and the form the package-URL `vcs_url` qualifier uses. CycloneDX has no field of its own for a revision, so the locator goes in the URL; a reader who sees `git+` knows to parse a revision from it rather than open it. A repository with nothing to pin stays a plain URL in CycloneDX, because that is a location a reader can open.

What each ecosystem yields:

| Ecosystem | Origin reported |
| --- | --- |
| npm, pnpm, yarn, bun | The registry tarball in the lockfile. Yarn Classic appends a checksum to the URL, which identifies contents rather than a location, so it is dropped. pnpm v9 entries that record only an integrity hash report nothing |
| uv, poetry, pipenv, pip | A repository plus the locked commit, or a direct archive URL, depending on the recorded source type |
| GitHub Actions | The repository named by the first two segments of a `uses:` reference, at the ref written after `@`: a commit when SHA-pinned, otherwise the tag or branch as written. A SHA-pinned step also keeps the commit as a `SHA-1` hash. Local references (`./path`, `$/path`) report nothing. The host is github.com; a repository scanned with `--url` from a GitHub Enterprise host reports no origin, because the workflow file does not say which host resolved the reference |
| cargo, Bundler, SwiftPM, pub | The repository and resolved commit for git dependencies. SwiftPM and pub read the commit from `Package.resolved` and `pubspec.lock`, whether or not the build tool ran |
| Go modules, Maven, Gradle, NuGet, others | Nothing yet; their manifests do not record a per-package location |
| Syft, ingested SBOMs | No detector origin |

With `--enrich` and the scorecard matcher selected, a package can also get a source repository resolved from its identity by OpenSSF Scorecard. It is used whenever the detector reported no repository, including for packages that already have a download location: an artifact and a repository answer different questions, so a package can carry both. The artifact stays the SPDX `downloadLocation` and CycloneDX `distribution` reference; the repository becomes the `vcs` reference and, in SPDX, the source info. A Scorecard repository is a network lookup, not a lockfile claim, so it is weaker evidence and carries no revision.

Four kinds of value are never published:

- **Registry and index roots** (`https://rubygems.org/`, `https://pub.dev`, the crates.io index). They say where an ecosystem fetches from, not where a package came from, and a private server URL out of context looks like a repository.
- **Local paths**: workspace members, editable installs, `file:` and `path:` dependencies. These describe the machine that ran the scan.
- **Non-web locations**: `ssh://`, `git@host:org/repo`, and similar transport addresses.
- **URLs with credentials.** A private registry URL can embed a token.

Every published origin is an absolute `http` or `https` URL with a host, a non-empty path, and no credentials. Values are re-serialized from a parse rather than copied, and the same check runs again at export, so a plugin's origin is held to the same rule as a built-in detector's. Both formats then compose the validated repository URL into the `git+<url>@<revision>` locator when a revision is recorded; CycloneDX keeps the plain URL when none is.

## Document identity

Every generated document carries:

- **A serial number.** A generated `urn:uuid` (CycloneDX `serialNumber`; the same value forms the SPDX document namespace, so the two exports of one scan can be correlated).
- **The producing tool and version** (CycloneDX `metadata.tools[]`; SPDX `Creator: Tool: bomly-cli-<version>`), plus one tool entry per detector that contributed.
- **A project version** on the primary component and the project's own modules: `git describe --tags --always --dirty` on the scanned checkout. When Git cannot describe it, the resolved commit is used, then the `--ref` value as typed. When none is available the version is omitted.
- **A CycloneDX lifecycle phase** (`pre-build` for source scans, `post-build` for images) and a **composition completeness** declaration: `complete` for unfiltered, warning-free scans, `incomplete` when `--scope` dropped part of the graph, `unknown` when resolution was degraded. SPDX 2.3 has no equivalent.
- **A primary component** for the scanned project. When the graph has one root, that root is the primary component. When a scan finds several manifests, Bomly synthesizes one named after the project with a `pkg:generic` PURL that depends on every root, so the exported graph is connected. The synthesized component is not repeated in the CycloneDX component list, and Bomly skips it when reading its own SBOMs.

Two cases change the serial number, and both apply only when the scan read SBOMs rather than lockfiles:

| Input | Identity of the output | Links to sources |
| --- | --- | --- |
| One source document (a conversion) | Keeps the source's identity. This is what makes export, read, export reproduce the same bytes. A CycloneDX serial can hold only a UUID URN, so an SPDX namespace that is not one is linked instead | None needed |
| Several source documents (a merge) | A new identity; a document has exactly one, and adopting a source's would name a document that is not this one | CycloneDX: a document-level `bom` external reference per source, carrying a BOM-Link (`urn:cdx:<serial>/<version>`) or the SPDX namespace URI, plus a SHA-256 checksum. SPDX: an `externalDocumentRefs` entry per source with the SHA-256 the specification requires. The checksum is computed while the source is read; a source that arrived without its bytes is left unnamed in SPDX rather than written as an invalid reference |

Source links are read back on import, so a merged document converted again still names the documents behind it. People and tools credited by any source are credited by the merged document.

## What enrichment adds

With `--enrich`, components are enriched from the package registry, keyed by PURL:

| Data | CycloneDX | SPDX 2.3 |
| --- | --- | --- |
| Licenses learned during matching (preferred over lockfile licenses) | `licenses` | `licenseDeclared` |
| Content digests | `hashes` | `checksums` |
| CPE identifiers | `cpe` | `SECURITY` / `cpe23Type` external references |
| Vulnerabilities | `vulnerabilities` array with ratings, CWEs, advisories, `affects`, and the VEX `analysis` block | `SECURITY` / `advisory` external references |
| End-of-life status | `bomly:eol*` properties | Package comment |
| Source repository from Scorecard | `vcs` reference, when the detector reported none | `sourceInfo` or `downloadLocation` |

Reachability results and other Bomly-specific data go to JSON output, not to the SBOM formats. See [Output formats](OUTPUT_FORMATS.md).

## Strict ingest limits

Bomly refuses a document whose JSON has more than one reading (see [What Bomly refuses to read](SBOM.md#what-bomly-refuses-to-read)). Checking for a repeated member name means remembering the names open in every object currently being read. Bomly refuses a document that would hold more than 100,000 open names or more than 16 MB of them. Neither format comes close: components live in an array, so only a handful of small objects are open at once, however many components the document lists.

## Preservation and conversion limits

Bomly preserves component identity (including PURL), dependency edges, roots, scope, package type, licenses, digests, CPEs, and the enrichment fields above whenever the destination format can hold them. An ingested document also keeps supplier, originator, description, homepage, copyright, its own external references, and its own assertions. Encoding is deterministic when the scan timestamp and document identifiers are fixed.

Some data becomes less specific when it crosses formats:

| Data | CycloneDX round trip | SPDX 2.3 round trip | Notes |
| --- | --- | --- | --- |
| Vulnerabilities | Kept in full: ratings, CWEs, affected refs, descriptions, advisory URLs, and the VEX `analysis` block (state, justification, responses, detail). A document that says a package is `not_affected` yields a scan that says so | Only the advisory reference survives, as an ordinary external reference | SPDX 2.3 has no slot for a rating or an analysis |
| End-of-life records | Kept (`bomly:eol*` properties) | Kept (package comment) | The matcher that asserted the record is not named, so a re-imported record has no `source`. Re-run with `--enrich` to attribute it |
| License claims | Kept | `licenseDeclared` and `licenseConcluded` are read as two claims and written back to the field each came from | Bomly concludes nothing itself |
| Decoded format version | Recorded on the scan document (`format`, for example `cyclonedx-1.6+json`), never re-emitted | Same | The output's own header says what the output is |
| Scope | The native field holds Bomly's projection (`required` for runtime, `excluded` for development-only); the full set travels in a `bomly:scopes` property | The full set travels in the `scope=` field of the package comment; SPDX has no native scope field | A Bomly document round-trips its scope set exactly. Reading the other way, CycloneDX `required` becomes runtime, and `optional` and `excluded` become development, because the specification defines an optional component as one that is not installed or reachable |
| Unknown scope tokens | Known tokens are kept; unknown ones are reported as a warning naming the file | Same | An unreadable token is almost always one a newer Bomly wrote |
| A source document's own scope word | Kept and written back: a component marked `optional` re-exports as `optional`, unless Bomly's own scope set stops meaning what the word meant | Not applicable; SPDX 2.3 has no scope field | |
| Package origin | Written on export, not read back | Same | Origin comes from a lockfile, and an ingested document is not one. `distribution` and `vcs` references are the shape of Bomly's own origin export, and nothing in a document separates Bomly's emission from a third party's, so reading them back would let a detector's guess re-enter as an assertion. SPDX also drops Bomly's `bomly-package-origin` reference and re-derives the `purl` and CPE references, so they do not grow on every round trip. Every other reference type is preserved as stated |
| Relationship confidence (`direct`, `transitive`, `unknown`), source provenance, reachability, findings, diagnostics | Not carried | Not carried | Report data, not SBOM fields. Use JSON |
| Multiple roots | Every root stays in the graph; the synthesized primary component links them | Same | An export that names no project falls back to the first root in deterministic order |
| Document identity across formats | A conversion is stable within a format, not across one | Same | A CycloneDX serial holds only a UUID URN, so an SPDX source converted to CycloneDX is linked rather than adopted, and converting back yields a different document |
| Namespace (`group`) | Kept | Recovered from the PURL only | SPDX 2.3 has no group field |
| Several licenses on one package | Listed as separate entries | Composed with `AND`; a value SPDX cannot hold verbatim becomes a `LicenseRef-*` | A list that went out as `A AND B` returns as the single expression `A AND B` |
| Component identifiers (`bom-ref`, `SPDXID`) | Not carried; identity is re-minted from the PURL | Same | Compare package URLs across a conversion, not identifiers |
| SPDX relationship types | Not applicable | Ingest accepts the whole `*_DEPENDENCY_OF` family; export writes only `DEPENDS_ON` and `DESCRIBES` | A `DEV_DEPENDENCY_OF` comes back as `DEPENDS_ON`; the development scope itself travels in the scope carrier |

## See also

- [SBOM formats](SBOM.md) — write, read, convert, and compare
- [Output formats](OUTPUT_FORMATS.md) — the `-o` rules and JSON output
- [SBOM detector](detectors/sbom/sbom.md) — ingest specifics
