# JSON schemas

Bomly's `--format json` output follows a stable, versioned schema. Every command shares the same vocabulary — `manifests`, `packages`, and `findings` — described in [Architecture → Domain model](ARCHITECTURE.md#domain-model). These pages are the per-command field references, generated from the source types so they never drift from the binary.

| Command         | Schema reference                       |
|-----------------|----------------------------------------|
| `bomly scan`    | [Scan output schema](schemas/scan.md)       |
| `bomly explain` | [Explain output schema](schemas/explain.md) |
| `bomly diff`    | [Diff output schema](schemas/diff.md)       |

## Quick start

Emit JSON instead of the text report, and pipe it to any tool that speaks JSON:

```sh
# Pretty-print the whole document
bomly scan . --format json | jq .

# List every package that has at least one vulnerability
bomly scan . --enrich --format json | jq '.packages[] | select(.vulnerabilities | length > 0) | .purl'

# Show packages with a complete version recommendation
bomly scan . --enrich --format json | jq '.packages[] | select(.remediation.status == "complete") | {purl, recommended_version: .remediation.recommended_version}'

# Write the document to a file for a later step
bomly scan . --format json --output scan.json
```

`bomly explain` and `bomly diff` accept the same `--format json` flag and emit documents that follow their respective schemas above.

## Output shape

The scan document is the SDK's scan record (`github.com/bomly-dev/bomly-sdk/scan`,
schema `bomly.scan.v1`). Every document carries a `schema_version` and a
`command`, then the three top-level collections, and the scan document adds
what a run says about itself:

- **`subject`** — what was scanned: `kind`, `repository_url`, `ref`, and the `commit_sha` the ref resolved to (or the working tree's HEAD for a local path inside a repository). Never a local path.
- **`run`** — the execution: `id`, `started_at`, `completed_at`, `tool` (`bomly` and its version), and `options` (`enrich`, `analyze`, `audit`, `fail_on`).
- **`verdict`** — `pass`, `warn` or `fail`, the same outcome the exit code reports, present when `--audit` ran.
- **`digests`** — a `sha256:` digest over each of `manifests`, `packages` and `findings`, so a reader can tell which section changed between two documents without comparing them.

The collections:

- **`manifests[]`** — detection-stage results, one entry per discovered project, each holding lean `dependencies[]` (identity, `scopes`, `depends_on`, and a `package_ref` into `packages`).
- **`packages[]`** — matching-stage artifacts, deduplicated by PURL, carrying the enrichment: `licenses`, `vulnerabilities` (OSV-aligned, with CVSS/EPSS/reachability and, when a source document stated one, the VEX `analysis`), `remediation`, `scorecard`, and `eol`. Each entry is the SDK package as the registry holds it: `name` and `org` are its coordinates (`@scope/name` on npm is `org: scope`, `name: name`), and every optional field is omitted when empty. `remediation` contains vulnerability fix status, a recommended version when the evidence is complete, and occurrence-specific suggestions. In each suggestion, `affected_dependency_refs` identifies occurrences of the vulnerable package. `suggested_action_dependency_ref` identifies the direct dependency or manifest anchor the action targets. These references and the manifest path keep workspaces and repeated packages distinct. Suggestions are read-only guidance, not commands that Bomly runs.
- **`findings[]`** — reference-style audit results that point back at the other collections rather than copying data inline: `package_ref` is the package URL (join `packages` by `purl`), `vulnerability_id` names the advisory inside `packages[].vulnerabilities`, `dependency_refs` lists the introducing `manifests[].dependencies` ids, and `decision`, when a resolver such as a baseline settled the `policy_status`, says which one and why.

Remediation status values are compact machine labels: `complete` means a
complete fix is available for every known vulnerability on the package;
`partial` means only some vulnerability evidence supports a fix;
`unavailable` means the sources explicitly report no fix; and `unknown` means
the evidence is missing or contradictory. Human-readable output expands these
to clearer fix-availability labels.

Enrichment lives once, in `packages`, and is resolved by PURL — so a CVE that affects a package shared by 50 dependencies appears a single time. `bomly diff` documents carry the same `packages` collection (the PURL-deduplicated union of the base and head states, head winning on conflict) so audit findings in the diff join the same way. See the per-command pages for the exact field-by-field breakdown.

## Stability

- The scan document's `schema_version` is `bomly.scan.v1`, the SDK's scan record schema: additive within v1 (new optional keys only), so tolerate unknown keys. Collections are always present: a collection with nothing in it is written as `[]`, never omitted and never `null`, so `jq '.findings[]'` or `.depends_on[]` works on a run that found nothing. This holds for the `scan`, `diff` and `explain` documents alike. Unset scalar fields and objects are still omitted.
- `diff` and `explain` keep the CLI's own `schema_version`, `1.0`. Their finding and package shapes follow the scan document's (`findings[].package_ref`, packages as SDK packages), which changed the shape of both without a version bump: the output had no external consumers at the time and the version now marks the schema families rather than promising the old field set.
- Additive, backward-compatible changes (new optional fields) bump a minor version; a breaking change bumps the major. Pin your consumers to the major version and tolerate unknown fields.
- The schema reference pages are regenerated by `make generate`, so they always match the binary you are running.

## Limitations

- A field is only populated when the corresponding stage ran: `vulnerabilities`, `remediation`, `scorecard`, and `eol` are present only with `--enrich`; `findings` only with `--audit`; `reachability` only with `--analyze`.
- An empty `vulnerabilities`/`findings` array means *nothing was reported under the options you ran with* — not a guarantee that the package is safe. In particular, reachability tiers are best-effort; a `tier: none`/unreachable result is a triage signal, not proof of safety (see [Reachability](REACHABILITY.md)).
- JSON output may contain absolute filesystem paths from the scanned target. Treat a scan document as potentially sensitive before publishing it.
