# Reachability

> ⚠️ **Experimental.** Reachability is opt-in (`--reachability`) and under active development. The output shape is stable, but ecosystem coverage is expanding and Tier-3 analyzers (`jsreach`, `pyreach`, `jvmreach`) report at package precision today — sufficient for triage, not a fix substitute. Do not use `--fail-on reachable` as the sole gate for security-critical decisions without understanding the limitations below.

`--reachability` runs code analysis on top of vulnerability matching to confirm whether a finding is actually reachable from your application code. Reachability annotations are attached to every applicable `PackageVulnerability` and copied onto each `Finding` when `--audit` is also set.

The point: stop chasing high-severity CVEs in transitive packages your code never imports.

## Quick start

```sh
# Annotate vulnerabilities with reachability (no audit required).
bomly scan --enrich --reachability --format json

# Fail only when a finding is BOTH low+ severity AND confirmed reachable.
bomly scan --enrich --audit --reachability \
  --fail-on low --fail-on reachable --format json
```

## Analyzer per ecosystem

| Ecosystem | Analyzer | Tier | What "reachable" means |
| --- | --- | --- | --- |
| Go | `govulncheck` | `symbol` | App code calls (transitively) the vulnerable function |
| JavaScript / TypeScript | `jsreach` | `package` | App source imports the npm package (directly or via the npm dep graph) |
| Python | `pyreach` | `package` | App source imports the PyPI distribution (directly or via the Python dep graph) |
| Java / Kotlin / Scala / Groovy | `jvmreach` | `package` | App source imports a class in the Maven artifact (directly or via the JVM dep graph) |

Other ecosystems are tracked for follow-up phases. On a project with no applicable analyzer, the pipeline runs cleanly and vulnerabilities keep their default `nil` reachability.

## "Unreachable" is **not** "safe" {#unreachable-is-not-safe}

This caveat applies to every Tier-3 analyzer (`jsreach`, `pyreach`, `jvmreach`) and is the single most important thing to understand before gating CI on `--fail-on reachable`.

Static analysis cannot see:

- Dynamic imports: `require(userInput)`, `importlib.import_module(name)`, `Class.forName(string)`.
- Runtime plugin loaders, entry-point discovery, Django `INSTALLED_APPS` strings, Spring component scanning, `ServiceLoader`, OSGi, JPMS dynamic layers, annotation-processed code.
- Build-time code generators or runtime shell-outs.

Tier-3 "unreachable" is a **triage signal**, not a fix substitute. Use it to deprioritize dev-only and transitive-but-unimported dependencies, not to dismiss vulnerabilities.

Tier-1 (`symbol`, Go) is much stronger: `govulncheck` builds the actual call graph. "Unreachable" at Tier-1 means there is no static call path. Even Tier-1 cannot see reflection, but the standard library's reflection use is well-understood and rare in app code.

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
| Go                   | `govulncheck` | `symbol`  | Backed by the vendored `golang.org/x/vuln/scan` library; runs in-process so users never need a `govulncheck` binary on PATH.                                                                                                                                     |
| JavaScript / TypeScript | `jsreach`     | `package` | Backed by the vendored `github.com/evanw/esbuild/pkg/api` library. Walks app source from `package.json` entry points (`main`, `module`, `browser`, `exports`, `bin`, plus implicit `index.*` / `app.js` / `server.js` / `main.js` fallbacks) and reports each npm package as reachable iff it appears in the import set. |
| Python               | `pyreach`     | `package` | In-process line-oriented import scanner. Walks every `.py` file under the project root (`pyproject.toml` / `setup.py` / `requirements*.txt` / `Pipfile` / `poetry.lock` / `pdm.lock` / `uv.lock`), records each top-level module from `import` and `from … import` statements, and maps module names to PyPI distribution names through a static override map (e.g. `yaml` → `PyYAML`) plus PEP 503 normalization. |
| Java / Kotlin / Scala / Groovy | `jvmreach`    | `package` | In-process line-oriented import scanner for JVM ecosystems (Maven, Gradle, SBT). Walks `.java` / `.kt` / `.kts` / `.scala` / `.groovy` source under the project root, scans top-of-file `import` statements (including Java `static`, Kotlin aliases, Scala selectors and wildcards), and maps Java/Kotlin/Scala package prefixes to Maven coordinates (`groupId:artifactId`) through a curated longest-prefix map. |

Other ecosystems (Java, Rust) are tracked for follow-up phases.
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

### A note on `pyreach` and Tier 3

`pyreach` reports at the **package tier** today using the same
"directly-imported set + transitive closure" approach as `jsreach`.
The analyzer walks every `.py` file under the project root, scans for
`import x` / `from x import …` statements, maps top-level module names
to PyPI distribution names, and then expands the resulting set
transitively through the Python detector's dep graph (via
`Graph.Dependencies`).

The module-to-distribution mapping is the part Python forces on every
static analyzer: imports use module names (`import yaml`,
`from PIL import Image`), but PyPI uses distribution names (`PyYAML`,
`Pillow`). The analyzer applies a layered mapping:

1. A small static override table for the well-known mismatches
   (`yaml → pyyaml`, `cv2 → opencv-python`, `sklearn → scikit-learn`,
   `bs4 → beautifulsoup4`, `PIL → pillow`, `jwt → pyjwt`, …).
2. PEP 503 identity normalization (lowercase, `_` / `.` → `-`) for
   everything else, which catches the bulk of PyPI (`requests`,
   `flask`, `numpy`, `pandas`, …).
3. Stdlib modules (`os`, `sys`, `json`, …) are dropped from the
   import set so they never affect the closure.

The same three caveats from `jsreach` apply, with two extra Python
specifics:

1. **"Unreachable" is not "safe".** `importlib.import_module(…)` on
   user input, plugin discovery via entry points, Django's
   `INSTALLED_APPS` strings, and conditional `__import__` calls are
   all invisible to a static scanner. Tier-3 unreachable is useful
   for prioritizing dev-only / unused dependencies, not as a fix
   substitute.
2. **Submodule imports collapse to the distribution.** `from
   urllib3.util import retry` attributes the whole `urllib3`
   distribution as reachable, even if a CVE only affects a
   different submodule. Symbol-tier resolution for Python is a
   future phase.
3. **A missing static-override entry produces a false negative for
   direct imports.** If a project does `import some_obscure_module`
   and the override map doesn't know it maps to `some-other-dist`,
   the analyzer reports the distribution as unreachable when it
   actually was imported. The BFS through the dep graph usually
   recovers the case via a transitive edge from a correctly-mapped
   neighbour. Adding an override is a one-line PR.
4. **The closure is only as accurate as the lockfile.** Same as
   `jsreach`: if the dep graph is incomplete, the closure can't
   reach what isn't there. The pip / poetry / pipenv / uv / pdm
   detectors are the source of truth for what edges exist.

### A note on `jvmreach` and Tier 3

`jvmreach` is the third Tier-3 analyzer and follows the same
"directly-imported set + transitive closure" shape as `jsreach`
and `pyreach`. It walks `.java` / `.kt` / `.kts` / `.scala` /
`.groovy` files under the project root, parses each top-of-file
`import` statement, and maps the FQN prefix to a Maven artifact
coordinate (`groupId:artifactId`) via a curated longest-prefix
map. The closure is then expanded transitively through
`Graph.Dependencies`.

The Java/Maven mapping problem is genuinely harder than Python's.
Python's `module → distribution` relationship is usually identity
modulo a small override table. The Java `package → Maven artifact`
relationship has no naming convention at all — `org.apache.commons`
covers ten different distributions, `com.google.common` is one
specific distribution, and there is no rule that holds in general.
Consequences:

1. **"Unreachable" is not "safe".** All the standard caveats apply:
   reflection, `ServiceLoader`, Spring component scanning, OSGi
   bundles, JPMS layers, and class-loader gymnastics are invisible
   to a static scanner. Annotation processors that generate code at
   build time also escape detection.
2. **The curated prefix map is small and biased toward popular
   libraries.** A missing prefix produces a false-negative for
   direct imports. The dep-graph BFS usually catches the case via
   a transitive edge from a correctly-mapped neighbour, but unlike
   Python there is no identity-normalization fallback. Adding a
   prefix is a one-line PR in
   `internal/analyzers/jvmreach/prefixmap.go`.
3. **Sub-package imports collapse to the artifact.** Importing
   `com.fasterxml.jackson.databind.ObjectMapper` flips the whole
   `jackson-databind` artifact reachable, even if the advisory
   affects only a different class in that artifact.
4. **The closure is only as accurate as the build manifest.** Same
   as `jsreach` / `pyreach`: if the Maven / Gradle / SBT detector
   doesn't see an edge, the closure can't follow it.

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
   metadata (`function`, `package`, `file`, `line`, `column`). Tier-3
   analyzers additionally populate:
   - `hops` — dep-graph distance from a directly-imported package.
     `0` means directly imported; higher values are transitive.
   - `confidence` — `high` (directly imported, no dynamic imports),
     `medium` (1–3 hops, no dynamic imports), or `low` (4+ hops or
     dynamic imports detected). Lets consumers triage long transitive
     chains without parsing `hops` themselves.
   - `dynamic_imports_detected` — `true` when the analyzer's scanner
     observed dynamic-import constructs in app source (e.g.
     `require(variable)`, `importlib.import_module(name)`,
     `Class.forName(string)`). When `true`, an "unreachable" verdict
     is necessarily incomplete; the confidence label is forced to
     `low` for reachable results as a triage signal.

2. **Text scan report** gains a "Reachability" line in the executive
   summary plus a `REACHABILITY` column in the findings table when
   `--reachability` is set. Each cell renders as `<status> (<tier>)`
   or `—` when no analyzer ran on that vulnerability.

3. **SARIF output** populates `result.codeFlows` from
   `Reachability.CallPaths` (one threadFlow per path, one location per
   frame with file/line/column), and a top-level `result.properties`
   exposes `reachability`, `reachability_tier`, `reachability_reason`,
   `analyzer`, `reachability_confidence`, `reachability_hops`, and
   `reachability_dynamic_imports_detected` for SARIF consumers that
   don't traverse codeFlows.

## Limitations

- **Tier-3 "unreachable" is not "safe"**: Package-tier results say "the
  app does not import this package", which is genuinely useful for
  prioritizing dev-only or transitive-but-unused dependencies, but it
  does not mean the vulnerability has been mitigated. See the
  `jsreach` notes above for the npm-specific shape of this caveat.
- **`govulncheck` requires a buildable Go module**. When the build
  fails, the analyzer returns `unknown` with one of the following
  stable `reason` codes so consumers can branch by failure mode:
  - `missing-toolchain` — `go` not on `PATH`, govulncheck binary
    missing, or runner not vendored.
  - `no-go-packages` — target dir has no `.go` files, build
    constraints exclude everything, or `go list` returns no matches.
  - `module-resolution-failed` — `go.mod` not found, missing
    `go.sum` entry, or `go: download` failed for a required module.
  - `invalid-go-mod` — `go.mod` syntax error.
  - `build-failed` — generic compile-stage failure (`syntax error`,
    `undefined:`, `imported and not used`, non-zero exit).
  - `cancelled` — context cancelled or deadline exceeded.
  - `runner-error` — fallback when none of the above patterns match.
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
- **`pyreach` does not follow dynamic imports.**
  `importlib.import_module(name)` on user input, plugin discovery via
  entry points, Django `INSTALLED_APPS` strings, conditional
  `__import__` — none of these are visible to a static scanner. The
  analyzer is a lower bound on what's actually reachable.
- **`pyreach`'s module-to-distribution map is hand-curated.** Missing
  an entry produces a false-negative for direct top-level imports.
  PRs to extend `internal/analyzers/pyreach/moduletodist.go` are
  welcome.
- **`jvmreach` does not follow reflection or runtime class loading.**
  Spring component scanning, `ServiceLoader`, OSGi, JPMS dynamic
  layers, and annotation-processed code are invisible to a static
  scanner.
- **`jvmreach`'s package-prefix map is hand-curated.** The Java
  `package → Maven artifact` relationship has no naming convention,
  so missing prefixes do not have an identity fallback. PRs to
  extend `internal/analyzers/jvmreach/prefixmap.go` are welcome.
- **`jvmreach` does not handle Gradle / Maven multi-module projects
  yet.** Each pom.xml / build.gradle root is treated as one
  project; modules under a parent are detected separately but
  attribution between modules is best-effort.

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

## Build layout

Unlike Syft and Grype, analyzers do not have a builtin/external build-tag
split. Both ship a single in-process implementation backed by a vendored
library:

- `govulncheck` runs in-process via `golang.org/x/vuln/scan`.
- `jsreach` runs in-process via `github.com/evanw/esbuild/pkg/api`.
- `pyreach` runs in-process via an in-tree line-oriented import
  scanner (no external dependency).
- `jvmreach` runs in-process via an in-tree line-oriented import
  scanner (no external dependency).

Both libraries are small enough that vendoring them outweighs the
maintenance cost of supporting an external/lite variant. Lite builds
(`make build-lite`) include the analyzers as-is.
