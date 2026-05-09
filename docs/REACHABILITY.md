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

| Ecosystem            | Analyzer      | Tier      | Notes                                                                                                                                                                                                                                                            |
| -------------------- | ------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Go                   | `govulncheck` | `symbol`  | Backed by `golang.org/x/vuln/scan`. The default build runs in-process; the `bomly_external_govulncheck` lite build shells out to a `govulncheck` binary on PATH.                                                                                                  |
| JavaScript / TypeScript | `jsreach`     | `package` | Backed by the vendored `github.com/evanw/esbuild/pkg/api` library. Walks app source from `package.json` entry points (`main`, `module`, `browser`, `exports`, `bin`, plus implicit `index.*` / `app.js` / `server.js` / `main.js` fallbacks) and reports each npm package as reachable iff it appears in the import set. The `bomly_external_jsreach` lite build is a no-op stub that reports `missing-toolchain`. |

Other ecosystems (Python, Java, Rust) are tracked for follow-up phases.
When `--reachability` is set on a project that has no applicable
analyzer for the languages present, the pipeline still runs cleanly:
vulnerabilities just keep their default `nil` reachability.

### A note on `jsreach` and Tier 3

`jsreach` reports at the **package tier** today. The analyzer
classifies a package as "reachable" when there is **any path** from
app source to that package through the dependency graph the npm
detector resolved from the lockfile:

- App source `require('express')` → `express` is reachable.
- `express` depends on `body-parser` per the lockfile → `body-parser`
  is reachable too, even if no app source file imports it directly.
- `jest` (a devDependency) is in the lockfile but no source file
  imports it → `jest` and everything reachable only through `jest`
  stay unreachable.

Concretely, esbuild walks the application's source tree (with
`PackagesExternal`, so it stops at every bare specifier without
opening `node_modules`), giving us the **directly-imported** set.
The analyzer then expands that set transitively through the npm
detector's existing dep graph (via `Graph.Dependencies`) before
deciding each package's status. Packages can appear in the dep
graph at multiple versions (a top-level `lodash@4` and a nested
`lodash@3` inside some sub-tree); we key the closure by graph IDs,
not names, so attribution stays version-correct.

Three important caveats:

1. **"Unreachable" is not "safe".** A server runtime can `require()`
   a package dynamically based on user input; a plugin loader can
   pull in a package at runtime; a build script can shell out to it.
   Static analysis cannot see those paths. Tier-3 unreachable is
   useful for triage prioritization (deprioritize dev-only and
   transitive-but-unimported), not as a fix substitute.
2. **Subpath imports collapse to the package name.** An import of
   `lodash/get` and `lodash/set` both attribute to `lodash`. If an
   advisory affects only `lodash/template`, jsreach still reports the
   whole `lodash` package as reachable when `lodash/get` is imported.
   Symbol-tier resolution for npm is tracked for a future phase and
   would need a curated affected-symbols database (OSV / GHSA rarely
   carry that level of detail for npm).
3. **The closure is only as accurate as the lockfile.** If the dep
   graph is incomplete (e.g. a package was installed locally but
   never recorded in the lockfile, or a package was installed via
   `npm link`), the closure can't reach it. The npm / pnpm / yarn
   detectors are the source of truth for what edges exist.

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
  does not mean the vulnerability has been mitigated. See the
  `jsreach` notes above for the npm-specific shape of this caveat.
- **`govulncheck` requires a buildable Go module**. When the build
  fails, the analyzer returns `unknown` with `Reason: build-failed`.
- **Multi-module / multi-project repos**: Attribution is best-effort.
  Each vulnerability is annotated by the first module/project pass
  that owns its package; better multi-root attribution will improve
  in a follow-up.
- **`jsreach` does not follow runtime / dynamic imports.** Calls like
  `require(somethingFromUserInput)`, plugin loaders, and worker
  threads are invisible to static analysis. The analyzer is therefore
  a "lower bound" on what's actually reachable.
- **`jsreach` does not handle yarn / pnpm workspaces yet**. The
  analyzer treats the directory containing `package.json` as a single
  project. Workspace-aware traversal (each workspace as its own
  project root with its own entry points) is a follow-up.

## Selecting analyzers

Use the `--analyzers` selector to restrict or extend the default set:

```sh
bomly scan --enrich --reachability --analyzers govulncheck
bomly scan --enrich --reachability --analyzers -govulncheck    # disable
bomly scan --enrich --reachability --analyzers govulncheck,jsreach
```

Selector syntax mirrors `--detectors`, `--matchers`, and `--auditors`:
bare names are an explicit include set, `+name` appends to defaults,
`-name` removes from defaults.

## Build-tag layout

Analyzers follow the same builtin/external split as Syft and Grype:

- Default build (`make build`): includes the in-tree analyzer
  implementations. `govulncheck` runs in-process via
  `golang.org/x/vuln/scan`; `jsreach` runs in-process via the vendored
  esbuild library.
- Lite build (`make build-lite`): adds `bomly_external_govulncheck`
  (shells out to `govulncheck` on PATH) and `bomly_external_jsreach`
  (no-op stub; lite users who need JS reachability should use the
  default build) so the binary stays small.
