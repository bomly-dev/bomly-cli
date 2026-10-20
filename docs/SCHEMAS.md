# JSON schemas

Bomly's `--format json` output follows a stable, versioned schema. This page is for people who write scripts or integrations against it. It explains the shape every command shares and points to the generated per-command field references, which are built from the source types so they never drift from the binary.

| Command | Field reference |
| --- | --- |
| `bomly scan` | [Scan output schema](schemas/scan.md) |
| `bomly explain` | [Explain output schema](schemas/explain.md) |
| `bomly diff` | [Diff output schema](schemas/diff.md) |

## Quick start

Write JSON instead of the text report and pipe it to any JSON tool:

```sh
bomly scan --format json | jq .                                                            # the whole document
bomly scan --enrich --format json | jq '.packages[] | select(.vulnerabilities | length > 0) | .purl'   # vulnerable packages
bomly scan --enrich --format json | jq '.packages[] | select(.remediation.status == "complete") | {purl, recommended_version: .remediation.recommended_version}'
bomly scan --format json -o json=scan.json                                                 # write to a file
```

`bomly explain` and `bomly diff` accept the same flag and follow their own schemas.

## Output shape

Every document carries a `schema_version` and a `command`, then three collections. The scan document also records what the run was about:

| Field | What it holds | Present |
| --- | --- | --- |
| `subject` | What was scanned: `kind`, `repository_url`, `ref`, and the `commit_sha` the ref resolved to (or the working tree's HEAD for a local path inside a repository). Never a local path | Always |
| `run` | `id`, `started_at`, `completed_at`, `tool` (`bomly` and its version), and `options` (`enrich`, `analyze`, `audit`, `fail_on`) | Always |
| `verdict` | `pass`, `warn`, or `fail`, the same outcome the exit code reports | With `--audit` |
| `digests` | A `sha256:` digest over each of `manifests`, `packages`, and `findings`, so a reader can tell which section changed between two documents | Always |

The three collections keep three kinds of data apart, so the same fact never appears twice:

| Collection | One entry per | What each entry holds |
| --- | --- | --- |
| `manifests[]` | Discovered project | The manifest's path and detector, and its `dependencies[]`: one per occurrence of a package, with identity, `scopes`, `depends_on`, and a `package_ref` into `packages` |
| `packages[]` | Unique package URL (PURL) | The enrichment data: `licenses`, `vulnerabilities` (OSV-aligned, with CVSS, EPSS, reachability, and the VEX `analysis` when a source document stated one), `remediation`, `scorecard`, and `eol`. `name` and `org` are the package's coordinates (`@scope/name` on npm is `org: scope`, `name: name`). Empty optional fields are omitted |
| `findings[]` | Audit result | A reference back into the other collections: `package_ref` is the PURL (join `packages` by `purl`), `vulnerability_id` names the advisory inside that package, `dependency_refs` lists the dependency IDs that introduce it, and `decision` says which resolver (for example a baseline) settled the `policy_status` and why |

Enrichment lives once, in `packages`, and is joined by PURL. A CVE on a package that 50 dependencies share appears one time. `bomly diff` documents carry the same `packages` collection, holding every package from both sides (the head version wins when they differ), so findings in a diff join the same way.

### Remediation

`packages[].remediation` carries the fix guidance for a package:

| Field | What it holds |
| --- | --- |
| `status` | `complete` (a fix is known for every vulnerability on the package), `partial` (only some), `unavailable` (the sources report no fix), or `unknown` (missing or contradictory evidence). Human-readable output expands these to longer labels |
| `recommended_version` | Present only when the evidence supports one complete recommendation |
| `suggestions[]` | One per occurrence. `affected_dependency_refs` names the dependencies that carry the vulnerable package; `suggested_action_dependency_ref` names the direct dependency or manifest the action targets. They differ for a transitive package |

Suggestions are guidance. Bomly never applies them.

## Stability

- The scan document's `schema_version` is `bomly.scan.v1`. `diff` and `explain` keep the CLI's own `1.0`; their finding and package shapes follow the scan document's.
- Within a version, changes are additive: new optional fields may appear, and existing fields keep their meaning. A breaking change gets a new version. Tolerate unknown fields.
- Collections are always present. An empty one is written as `[]`, never omitted and never `null`, so `jq '.findings[]'` works on a run that found nothing. Unset scalar fields and objects are omitted.
- The field references under `schemas/` are regenerated from the source types by `make generate`, so they match the binary you run.

## Related shapes

- [MCP server](MCP.md#what-the-tools-return) describes the compact `mcp/1` shape the MCP tools return, which is versioned separately.
- [SARIF](OUTPUT_FORMATS.md#sarif) follows the SARIF 2.1.0 specification, not this schema.

## Limitations

- A field is filled only when its stage ran: `vulnerabilities`, `remediation`, `scorecard`, and `eol` need `--enrich`; `findings` needs `--audit`; `reachability` needs `--analyze`.
- An empty `vulnerabilities` or `findings` array means nothing was reported with the options you ran, not that the package is safe. A reachability result of `unreachable` is a triage signal, not proof of safety; see [Reachability](REACHABILITY.md).
- JSON output can contain absolute paths from the scanned target. Treat a scan document as potentially sensitive before you publish it.
