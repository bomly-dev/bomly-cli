# SDK Maturity Program

- **Date:** 2026-08-26
- **Owners:** bomly-sdk and bomly-cli maintainers
- **Decisions:** [ADR-0036](adr/0036-dependency-identity-is-content-addressable.md)
  (content-addressable identity), [ADR-0037](adr/0037-sbom-assertions-are-typed-sdk-model-fields.md)
  (typed SBOM model), [ADR-0038](adr/0038-purl-and-spdx-behavior-have-one-home-in-the-sdk.md)
  (PURL/SPDX single home), [ADR-0039](adr/0039-both-modules-build-on-go-1-27.md)
  (Go 1.27, strict untrusted parsing)

This document is the execution plan for those four decisions: what ships in
which repository, in what order, and how we know the program is done. The
goal is that future bugs land in one place with one fix, and new features
start from a model that already carries what they need.

The principle the whole program applies is recorded as a standing rule in
[ADR-0040](adr/0040-the-sdk-is-the-default-home-for-behavior.md): behavior
about shared domain objects lands in the SDK first, and the CLI and plugins
keep only what is theirs by nature — so finishing this program is not a
one-time cleanup but the point after which drift stops being the default.

## 1. Why now

The last month of fixes shows one pattern: real defects, each patched at the
site where it surfaced, because the rule that should have prevented it had no
home.

| Fix | Underlying gap |
|---|---|
| PR #406 — scopes lost when duplicate nodes fold; four detectors had private patches, ten silently dropped data | No single owner for node identity and fold semantics |
| PR #407 — cargo workspace member misidentified by name alone; a real dependency vanished from matching | Same — identity resolved ad hoc per detector |
| PR #409 — license shape decided by which field carried the value; first revision corrupted every namespaced name on ingest | No SDK license classification; Org/Name split invertible only by heuristics |
| Issue #410 — SPDX free-text license emitted verbatim; every `--sbom` ingest loses `Org` (0 of 24 survive a round trip) | No `LicenseRef` machinery; no canonical name-split inverse |
| Issue #396 / closed PR #391 — ingest drops supplier, checksums, CPEs, references; 20 review rounds could not make metadata-key smuggling safe | The model cannot carry SBOM assertions as typed, gated fields |

The SDK sits at v0.4.2 with a stated policy that v0 minors may adjust the
in-process Go API. That window is the cheapest this program will ever be;
after a v1 freeze every one of these changes becomes a major-version event.

## 2. Current state (survey, 2026-08-26)

Full details live in the ADR context sections; the load-bearing facts:

**Identity.** Three notions, none sufficient: `Dependency.ID` defaults to
`StableID()` = `org:name@version` (not ecosystem-qualified — npm and PyPI
`left-pad@1.0.0` collide); `IdentityKey()` is versionless diff grouping; the
canonical PURL keys the registry, but the SDK cannot *reconstruct* qualifiers
or subpath — an existing valid PURL keeps them through canonicalization,
while the `BuildPackageURL` fallback accepts only type, namespace, name, and
version — and the PURL-as-ID rewrite happens at three sites with three
fallback chains
(`internal/engine/consolidation/enrichment.go:26`,
`internal/detectors/sbom/detector.go:164`, `internal/sbom/graph.go:37` — only
the first canonicalizes). Nothing is content-addressable.

**SBOM field coverage.** The SDK has no supplier, originator, description,
homepage, external references, declared-vs-concluded license distinction,
typed edges, or document-level assertions. `ToGraph` discards CPEs, digests,
vulnerabilities, EOL, and origin URLs on ingest. `LicenseType` has one value.
Digest algorithms are two string constants. The `Metadata` map is the only
escape hatch and does not survive the plugin wire as typed values.

**Duplication.** purl-type → ecosystem mapping exists twice and disagrees on
`hex` (`internal/sbom/identity.go:25` vs `internal/benchmark/summary.go:349`);
`internal/cli/render/explain.go:118` parses PURLs by string surgery; 13
detectors hardcode purl-type literals while 6 derive them; a hand-maintained
18-entry deprecated-SPDX-ID replacement table lives inside the SBOM codec
instead of with the license machinery (`internal/sbom/transform.go:455`); `ingestedCoordinateOrg`
(`internal/sbom/graph.go:122`) inverts `EcosystemName()` by prefix matching;
`matcherkit.NormalizeLicenseSet` writes raw strings into `SPDXExpression`
unvalidated; `internal/licenseexpr` (the panic-guarded SPDX parser) is
unreachable from plugins that need it.

**Fidelity defects found by this survey** (previously unreported — file as
issues when the program starts):

1. **CycloneDX scope does not round-trip.** Encode maps
   `runtime→required` / `development→excluded` (`cyclonedx.go:374`), but
   decode copies the raw token back (`cyclonedx.go:113,161`) and
   `graph.go:48` mints nodes scoped `"required"`/`"excluded"` — values
   outside the SDK vocabulary. No reverse mapping exists; tests cover only
   the forward direction.
2. **PR #406's scope union is discarded at export.** `transform.go:44`
   exports `PrimaryScope()` — a single value — so a `[runtime, development]`
   node loses the union at the SBOM boundary.
3. **SPDX drops licenses on mixed validity.** `spdxLicenseValue`
   (`spdx23.go:441`) falls back to `values[0]` when any member fails to
   parse; CycloneDX's equivalent loses nothing. (Resolved by #410's
   `LicenseRef` composition.)
4. **SPDX writes `eol=`/`eol_date=` package-comment fields it never reads
   back** (`spdx23.go:336` vs `:160,:397`).
5. **ADR-0033's prose is stale**: it still says `EnsureNode` "deliberately
   merges nothing"; #406 made scopes union. Supersede or annotate.

**Go.** Both modules declare `go 1.26.3`. Go 1.27 shipped this month with
`encoding/json/v2` (strict duplicate-key/UTF-8 rejection — a smuggling
defense for SBOM ingest), stdlib `uuid`, generic methods, `strings.CutLast`.

## 3. Target architecture

One sentence per decision; the ADRs carry the detail.

- **Identity** (ADR-0036): identity facets defined once in the SDK — a
  readable ID (canonical PURL + hashed occurrence suffix) and a derived
  128-bit content address over a versioned facet encoding — minted only by
  SDK entry points.
- **Model** (ADR-0037): every preserved SBOM assertion is a typed,
  `omitempty`, boundary-validated field with a declared merge class; typed
  edges; a per-entry document-assertions carrier on `GraphEntry`; `Metadata`
  returns to being an escape hatch.
- **Kits** (ADR-0038): `purlkit` (parse/build/canonicalize with qualifiers +
  subpath, the one type-mapping table, `SplitEcosystemName`, the one
  canonical-ID rewrite) and `spdxkit` (panic-guarded expression handling,
  deprecated-ID canonicalization, classification-by-validation, `LicenseRef`
  minting) — with import-boundary guard tests in both repos.
- **Toolchain** (ADR-0039): both modules on Go 1.27; untrusted-document
  parsers on json/v2 strict; stdlib `uuid`; one reviewed modernizer pass.

## 4. Execution phases

Ordering rule throughout (existing policy): **the SDK tags first, plugin
repositories adopt the new tag, then the CLI updates its pin.** Every phase
lands as normal PRs; nothing goes to main directly.

### Phase 0 — Groundwork (small, independent PRs)

| # | Repo | Work | Notes |
|---|---|---|---|
| 0.1 | sdk | Add an API-compatibility gate to CI (`gorelease`/`apidiff`) | Survey found none; prerequisite for doing deliberate breaks knowingly |
| 0.2 | sdk, cli, plugins | Go 1.27 toolchain bump: `go` directives, CI matrices, release builders, CONTRIBUTING; absorb `go mod tidy` reshape and `stdversion` vet. The nine `bomly-plugin-*` repos are part of this phase — a 1.27 SDK raises their minimum toolchain, so each must move before adopting the first 1.27 SDK tag | ADR-0039 |
| 0.3 | cli | File the five survey defects as issues; fix the SPDX eol comment read-back now (codec-local, CLI-owned behavior). The CycloneDX scope reverse-mapping fix is an explicit ADR-0040 loan: its durable home is the SDK scope mapping (1.4), so the CLI patch ships only with the SDK issue filed and linked from the code, and is replaced in 2.6 | The loan is taken because every CDX ingest today mints invalid scope values — waiting for phase 1.4 leaves a live bug |
| 0.4 | cli | ADR-0033 stale-prose correction (supersede note re: scope union) | Doc-only |

### Phase 1 — SDK maturity (bomly-sdk v0.5.x → v0.7.x)

Breaking in-process changes are allowed (v0 policy); the wire stays additive
`bomly.plugin.v1` throughout, enforced by the existing frozen-fixture tests.

| # | Work | Ships |
|---|---|---|
| 1.1 | `purlkit`: qualifiers/subpath-capable build/parse/canonicalize; the single purl-type ↔ ecosystem table (hex non-mapping recorded); `SplitEcosystemName`; canonical-ID rewrite entry point; import-boundary guard | v0.5.0 |
| 1.2 | `spdxkit`: absorb `internal/licenseexpr` semantics (panic guards, `Valid`/`ValidateAll`/`Identifier`/`Compose`/`Satisfies`/`Extract`); deprecated-ID canonicalization via the audited replacement map relocated from `internal/sbom/transform.go` (the list marks deprecation; the map owns replacements); classification-by-validation; deterministic `LicenseRef-*` minting + extracted-text pairing; fix `matcherkit.NormalizeLicenseSet` to classify on write | v0.5.0 |
| 1.3 | Identity (ADR-0041, superseding ADR-0036): typed `GraphNode` union (`PackageNode` requires a valid canonical PURL — type+name mandatory, missing version warned; `ManifestNode` is structural, path-identified, never matched); identity equals/key comparison over (canonical PURL, normalized origin); PURL-based readable IDs with deterministic run-local ordinals for contradicting occurrences; single insertion + finalization entry points; wire flat-node shape kept with an additive kind discriminator; no content address | v0.6.0 |
| 1.4 | Model fields (ADR-0037): supplier/originator/description/homepage; `ExternalReference`; `PackageLicense` declared/concluded + extracted text; digest-algorithm registry; set-aware scope ↔ CycloneDX mapping with its scalar projection rule; typed `DependencyEdge.Kind` with a kind-preserving edge-copy/rename primitive for graph reconstruction sites; usage attribution (`PackageLocation` carries per-site scopes and relationship so the node-level union becomes derived; reachability becomes repeatable per-module-root evidence with the vulnerability annotation as derived summary, and evidence may carry optional `DependencyRefs` to the exact occurrence nodes where the analyzer can attribute — a conjunctive filter such as reachable ∧ runtime ∧ direct then joins evidence to locations within one module root, selecting one usage); a derived package → nodes reverse-index helper (the stored truth stays `Dependency.PackageRef`; the registry remains position-free); per-`GraphEntry` document assertions; per-field-class merge helpers; boundary validation codecs + fuzz targets for every new parser | v0.7.0 |
| 1.5 | Metadata policy: document reserved `bomly.` prefix; deprecate `MetadataKeyDetectionLicenses` in favor of the typed license field | v0.7.0 |

Each SDK release is followed immediately by Dependabot-or-manual pin bumps in
the nine `bomly-plugin-*` repos (matcherkit and licence-writing matchers are
the ones that materially change at 1.2).

### Phase 2 — CLI adoption and cleanup (one coordinated train)

The pin bump to v0.7.x and the following land as a short stacked series so
the golden refresh happens **once**:

| # | Work | Replaces |
|---|---|---|
| 2.1 | Adopt `purlkit`: delete `internal/sbom/identity.go` table, `benchmark/summary.go` table, `render/explain.go` string surgery; detectors derive purl types (guard test forbids literals); one canonical-ID rewrite in consolidation, reused by SBOM ingest paths | Findings §2 duplication items |
| 2.2 | Adopt `spdxkit`: delete `internal/licenseexpr`; the deprecated-ID replacement map relocates into the kit; export/import use kit classification | ADR-0035 stays behavioral truth, now SDK-enforced |
| 2.3 | Adopt identity: node IDs SDK-derived end to end; regenerate schemas, goldens, smoke; release-notes callout for the one-time ID change | ADR-0036 |
| 2.4 | **Close #410**: `LicenseRef-*` + `hasExtractedLicensingInfos` emission, mixed-validity composition, canonical ingest coordinates via `SplitEcosystemName`; round-trip asserts `Org`+`Name`+`EcosystemName()` together | Also removes ADR-0035's recorded limitation |
| 2.5 | **Close #396** on the typed model: ingest populates typed fields through their gates; the export surface takes the prepared entries rather than the bare merged graph, so per-entry document assertions reach the codec; export projects them; merge follows the declared classes; fixed-point test (single-source export → ingest → export byte-stable for preserved fields; a merged export links source identities per ADR-0037, with merged fixtures for both formats validated through the codecs and the official format validators); hostile-document fuzz coverage | Deferred #391 items stay deferred per ADR-0037 |
| 2.6 | Export full scope sets (fixes survey defect 2) and adopt json/v2 strict ingest with documented rejection behavior, and pin the v1 plugin wire's lenient decode with SDK wire fixtures so the migration cannot tighten it by accident | ADR-0039 |
| 2.7 | Registry-lookup and PURL-fallback helper consolidation across output/render/tui/mcp presentation layers, built on the SDK's derived reverse-index/lookup helper | Survey §3 items 5–6 |
| 2.8 | Usage-attribution adoption: native detectors record per-site scopes, relationship, and the owning module root on locations; the four analyzer repos emit per-module-root reachability evidence, with optional `DependencyRefs` to exact occurrence nodes where attributable — govulncheck via build module versions, jsreach via nested `node_modules` locations (behavioral bumps, not mechanical); CLI filtering, rendering, and MCP join conjunctive filters through attribution; regression test for the workspace case where a package is direct-in-dev in one module and transitive-at-runtime in another | Without producer and consumer migration the 1.4 fields stay empty and the conjunction cannot work |

### Phase 3 — Hardening and documentation

- Guard tests as first-class deliverables: no direct `packageurl-go`/
  `go-spdx` imports outside kits; no hand-built PURL strings; no node-ID
  minting outside SDK entry points; no second mapping tables.
- `make generate` drift committed wherever config/output surfaces moved;
  `docs/SBOM.md` preservation-limits section rewritten to the new (shorter)
  truth; `dev-docs/MODELS.md` updated for identity facets and typed fields;
  `CLAUDE.md`/`AGENTS.md` package maps updated.
- Smoke: dispatch Update Smoke Goldens once after 2.3 and once after 2.5;
  keep `test/smoke/testdata/scan_targets.json` and the benchmark list in
  sync.
- A modernizer (`go fix`) pass per repo, reviewed as its own PR.

## 5. Compatibility and risk

| Risk | Position |
|---|---|
| Node IDs change in scan JSON, bom-refs, `DependencyRefs` | One-time, phase 2.3 only, schemas regenerated, release-notes callout. Baselines key on package + finding references, not node IDs — verify with a baseline round-trip test before merging 2.3 |
| Plugin wire compatibility | All model additions `omitempty`; frozen v1 fixtures must keep decoding; no field is renamed or repurposed. The wire-compat tests are the gate, extended per addition |
| Nine plugin repos pinned to the SDK | Standard ordering (SDK tag → plugin bumps → CLI pin). Matcher repos change behavior (license classification on write) and the four analyzer repos adopt per-module reachability evidence (2.8); the remaining bumps are mechanical |
| json/v2 strict ingest rejects previously-parsed SBOMs | Deliberate and documented; the rejection error names the duplicate key or the invalid byte sequence. Only ingest is strict — the plugin wire keeps v1 semantics |
| Golden churn | Batched to two refreshes (after 2.3, after 2.5); smoke runs capped at 5m per invocation as established |
| `pub-native`/`swiftpm-native`/`sbt-native` graph-shape expectations | Run local benchmark + smoke with `dart`/`swift`/`sbt` on PATH before accepting shape drift in 2.3 |
| SDK v1 pressure | Do **not** cut v1 during this program; v1 is the program's exit criterion, cut only after the CLI and all plugins run on the final surface for one release cycle |

## 6. Definition of done

1. Issues #410 and #396 closed by phase-2 PRs; survey defects 1–4 closed;
   ADR-0033 prose corrected.
2. `bomly scan` → export → ingest → export is a fixed point for every
   preserved field, and a self-scan round trip preserves `org` for 24/24
   packages (today: 0/24).
3. Grep-level: zero purl-type string literals in detectors, zero
   `packageurl-go`/`go-spdx` imports outside the kits, zero PURL string
   concatenation outside `purlkit` — each enforced by a guard test, not a
   review habit.
4. One identity authority: every node ID and content address in the pipeline
   is produced by an SDK entry point, and `left-pad@1.0.0` from two
   ecosystems are two nodes in one merged graph, proven by test.
5. Both modules on Go 1.27; untrusted SBOM ingest rejects documents with
   duplicate object names or invalid UTF-8, each with an actionable error.
6. `dev-docs/MODELS.md`, `docs/SBOM.md`, generated docs, and goldens reflect
   the final state; SDK CI carries an API-compatibility gate.

When all six hold for one full release cycle, propose the SDK v1 freeze as
its own ADR.
