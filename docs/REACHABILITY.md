# Reachability

Bomly's `--reachability` flag runs code analysis on top of vulnerability
matching to confirm whether a finding is actually reachable from the
application code. Reachability annotations are attached to every
applicable `PackageVulnerability` and copied onto each `Finding` when
`--audit` is also set.

## Quick start

```sh
# Annotate vulnerabilities with reachability (no audit required).
bomly scan --enrich --reachability --format json

# Audit + reachability constraints AND-ed via repeatable --fail-on.
# Only low+ severity vulnerabilities that are confirmed reachable
# become findings.
bomly scan --enrich --audit --reachability --fail-on low --fail-on reachable --format json
```

## How it works

The pipeline gains a new `analyze` stage between `match` and `process`:

```
detect → consolidate → match → analyze → process → audit
```

When `--reachability` is set, every applicable `Analyzer` runs against
the matched graph. Analyzers dispatch on `(Language, Ecosystem,
PackageManager)` and may produce results at three levels of precision
(`Tier`):

| Tier      | Meaning                                                                |
| --------- | ---------------------------------------------------------------------- |
| `symbol`  | Exact call graph from app code into the vulnerable function or method. |
| `module`  | App imports the vulnerable submodule, but no symbol-level evidence.    |
| `package` | App imports (or doesn't import) the package; nothing else is known.    |
| `none`    | No analysis was performed (`Status=unknown` always uses this tier).    |

Each analyzer reports one of four statuses per vulnerability:

| Status            | Meaning                                                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------- |
| `reachable`       | App code reaches the vulnerable symbol(s) at the chosen tier.                                       |
| `unreachable`     | Analyzer ran successfully but did not find a path. **At `package` tier this does not mean "safe"**. |
| `unknown`         | Analyzer was applicable but could not determine reachability. `Reason` carries the cause.           |
| `not_applicable` | Analyzer cannot evaluate this vulnerability (e.g. no language match, no source available).         |

Analyzer failures **never abort the pipeline**. Missing toolchains,
broken builds, cancelled contexts, and other recoverable conditions all
degrade to `Status: unknown` with a stable, machine-readable `Reason`
(e.g. `missing-toolchain`, `build-failed`, `cancelled`,
`no-module-root-discovered`).

## Ecosystem support

Phase A ships a single analyzer:

| Ecosystem | Analyzer       | Tier     | Notes                                                                                                          |
| --------- | -------------- | -------- | -------------------------------------------------------------------------------------------------------------- |
| Go        | `govulncheck`  | `symbol` | Backed by `golang.org/x/vuln/scan`. The default build runs in-process; the `bomly_external_govulncheck` lite build shells out to a `govulncheck` binary on PATH. |

Other ecosystems (JavaScript/TypeScript, Python, Java, Rust) are tracked
for follow-up phases. When `--reachability` is set on a project that has
no applicable analyzer for the languages present, the pipeline still
runs cleanly: vulnerabilities just keep their default `nil` reachability.

## Composing with `--fail-on`

`--fail-on` is repeatable; constraints AND together. Two kinds are
supported today:

- Severity: `any | low | medium | high | critical`
- Reachability: `reachable`

```sh
# All findings (legacy single-string form still works).
bomly scan --enrich --audit --fail-on any

# Equivalent — Bomly defaults to "any" when no severity is supplied.
bomly scan --enrich --audit

# Low+ severity only.
bomly scan --enrich --audit --fail-on low

# Low+ severity AND confirmed reachable. nil reachability (no analyzer
# ran on this vulnerability) does NOT match — the analyzer must have
# affirmatively proven reachability.
bomly scan --enrich --audit --reachability --fail-on low --fail-on reachable
```

Future constraint kinds (e.g. `kev`, `has-fix`, `epss>0.5`) can be
added without further flag changes.

## Output shape

Reachability data appears in three places:

1. **JSON output** under each `vulnerabilities[].reachability` and (when
   `--audit` is set) `findings[].reachability`. The reachability object
   carries `status`, `tier`, `analyzer`, optional `reason`, optional
   list of confirmed `symbols`, and optional `call_paths` with frame
   metadata (`function`, `package`, `file`, `line`, `column`).

2. **Text scan report** gains a "Reachability" line in the executive
   summary plus a `REACHABILITY` column in the findings table when
   `--reachability` is set. Each cell renders as `<status> (<tier>)`
   or `—` when no analyzer ran on that vulnerability.

3. **SARIF output** populates `result.codeFlows` from
   `Reachability.CallPaths` (one threadFlow per path, one location per
   frame with file/line/column), and a top-level `result.properties`
   exposes `reachability`, `reachability_tier`, `reachability_reason`,
   and `analyzer` for SARIF consumers that don't traverse codeFlows.

## Limitations

- **Tier-3 "unreachable" is not "safe"**: Package-tier results say "the
  app does not import this package", which is genuinely useful for
  prioritizing dev-only or transitive-but-unused dependencies, but it
  does not mean the vulnerability has been mitigated.
- **`govulncheck` requires a buildable Go module**. When the build
  fails, the analyzer returns `unknown` with `Reason: build-failed`.
- **Multi-module repos**: The current attribution is best-effort. Each
  Go vulnerability is annotated by the first module pass that owns its
  package; multi-module attribution will improve in a follow-up.
- **No caching yet**: Each analyzer run invokes the underlying tool from
  scratch. A FileCache wrapper around the `internal/matchers/cache`
  helper is planned.

## Selecting analyzers

Use the `--analyzers` selector to restrict or extend the default set:

```sh
bomly scan --enrich --reachability --analyzers govulncheck
bomly scan --enrich --reachability --analyzers -govulncheck   # disable
```

Selector syntax mirrors `--detectors`, `--matchers`, and `--auditors`:
bare names are an explicit include set, `+name` appends to defaults,
`-name` removes from defaults.

## Build-tag layout

Analyzers follow the same builtin/external split as Syft and Grype:

- Default build (`make build`): includes the in-tree analyzer
  implementations.
- Lite build (`make build-lite`): adds `bomly_external_govulncheck` so
  the binary stays small and shells out to `govulncheck` on PATH.
