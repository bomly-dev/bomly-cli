# Reachability

> **Experimental.** Reachability is opt-in (`--analyze`) and still maturing. The output shape is stable, but ecosystem coverage is growing, and the JavaScript, Python, and JVM analyzers work at package precision: they confirm that your code imports the vulnerable package, not that it calls the vulnerable function. Read [Unreachable is not safe](#unreachable-is-not-safe) before you gate CI on it.

Reachability answers one question per vulnerability: can the scanned project reach the vulnerable code at all? Use it to stop chasing high-severity advisories in transitive packages your code never imports. This page explains what the analyzers check, what the results mean, and where they appear.

## Quick start

`--analyze` requires `--enrich`, because it annotates the vulnerabilities enrichment found:

```bash
# Annotate vulnerabilities with reachability
bomly scan --enrich --analyze --json

# Fail only when a finding is both low-or-higher severity and confirmed reachable
bomly scan --enrich --audit --analyze --fail-on low --fail-on reachable
```

## What each analyzer checks

Each analyzer handles one language and reports at one level of precision, called a tier.

| Ecosystem | Analyzer | Tier | "Reachable" means | Prerequisites |
| --- | --- | --- | --- | --- |
| Go | `govulncheck` | `symbol` | Application code calls the vulnerable function, directly or through other calls. Built on the Go vulnerability database tooling, run in-process | A Go module that builds (`go` on `PATH`) |
| JavaScript, TypeScript | `jsreach` | `package` | Application source imports the npm package, directly or through the dependency graph the lockfile describes | A `package.json` with entry points, and a lockfile |
| Python | `pyreach` | `package` | Application source imports the PyPI distribution, directly or through the dependency graph | `.py` sources under the project root |
| Java, Kotlin, Scala, Groovy | `jvmreach` | `package` | Application source imports a class from the Maven artifact, directly or through the dependency graph | Sources under the project root, and a Maven, Gradle, or SBT graph |

On a project with no applicable analyzer, the scan runs normally and every vulnerability keeps an empty reachability result.

The tiers, from strongest to weakest:

| Tier | Meaning |
| --- | --- |
| `symbol` | A call graph from application code reaches the vulnerable function or method |
| `module` | Application code imports the vulnerable submodule, with no symbol-level evidence |
| `package` | Application code imports, or does not import, the package. Nothing more is known |
| `none` | No analysis ran. A status of `unknown` always uses this tier |

Each analyzer reports one of three statuses per vulnerability, or leaves it empty when the vulnerability is outside its scope:

| Status | Meaning |
| --- | --- |
| `reachable` | Application code reaches the vulnerable code at the reported tier |
| `unreachable` | The analysis completed and found no path. At the `package` tier this does not mean safe |
| `unknown` | The analyzer applied but could not finish. `reason` says why |

Analyzer failures never stop a scan. A missing toolchain, a broken build, or a cancelled run becomes `unknown` with a machine-readable reason such as `missing-toolchain` or `build-failed`.

## Unreachable is not safe

This is the most important thing to know before you gate CI on `--fail-on reachable`. Static analysis cannot see:

- **Dynamic imports**: `require(userInput)`, `importlib.import_module(name)`, `Class.forName(string)`, conditional `__import__`.
- **Runtime loaders**: plugin systems, Python entry points, Django `INSTALLED_APPS` strings, Spring component scanning, `ServiceLoader`, OSGi, JPMS layers, reflection.
- **Generated or external code**: annotation processors, build-time code generators, shell commands.

A package-tier `unreachable` says "the application does not import this package". That is useful for deprioritizing dev-only and unused transitive dependencies. It is not evidence that the vulnerability is mitigated. The Go `symbol` tier is much stronger, because `govulncheck` builds the real call graph, but even it cannot see reflection.

When an analyzer sees dynamic-import constructs in your source, it sets `dynamic_imports_detected` to `true` and lowers the confidence of its results, so you can tell from the output when an `unreachable` verdict is incomplete.

## Package-tier analysis in brief

`jsreach`, `pyreach`, and `jvmreach` all work the same way. They scan application source for import statements to build the set of directly imported packages, then expand that set through the dependency graph the detector resolved. Any package reachable from the imported set is `reachable`; everything else, such as a dev dependency no source file imports, is `unreachable`.

Three consequences follow for all three:

- **Imports of a subpath count for the whole package.** Importing `lodash/get` marks all of `lodash` reachable, even if an advisory affects only `lodash/template`.
- **The result is only as good as the lockfile or build manifest.** A package installed locally but never recorded, or a dependency the build tool did not report, cannot be reached.
- **Python and JVM imports must be mapped to package names.** `import yaml` means the `PyYAML` distribution, and `org.apache.commons` covers many Maven artifacts. Both analyzers use curated maps for the well-known cases, so a missing entry can produce a false `unreachable` for a direct import. If you find one, open an issue naming the import and the package; additions are quick to ship.

The per-analyzer details, including the override maps and workspace handling, are in the [reachability internals](https://github.com/bomly-dev/bomly-cli/blob/main/dev-docs/REACHABILITY_INTERNALS.md) for contributors.

## Gating on reachability

`--fail-on` is repeatable, and the vulnerability constraints must all match (they combine with AND). An empty reachability result, meaning no analyzer ran on that vulnerability, never matches `reachable`: the analyzer must have confirmed it.

```bash
bomly scan --enrich --audit --fail-on low                                   # severity only
bomly scan --enrich --audit --analyze --fail-on low --fail-on reachable      # severity AND reachable
```

The full list of `--fail-on` values, including `exploitable`, is on the [Auditors](AUDITORS.md) page.

## Where the results appear

| Output | What you see |
| --- | --- |
| JSON | A `reachability` object on each `vulnerabilities[]` entry and, with `--audit`, on each `findings[]` entry: `status`, `tier`, `analyzer`, optional `reason`, `symbols`, and `call_paths` (with `function`, `package`, `file`, `line`, `column`). Package-tier analyzers add `hops` (graph distance from a directly imported package; `0` means directly imported), `confidence` (`high`, `medium`, or `low`), and `dynamic_imports_detected` |
| Text report | A "Reachability" line in the summary and a `REACHABILITY` column in the findings table, rendered as `<status> (<tier>)`, or `—` when no analyzer ran |
| SARIF | `result.codeFlows` built from the call paths, plus `result.properties` with `reachability`, `reachability_tier`, `reachability_reason`, `analyzer`, `reachability_confidence`, `reachability_hops`, and `reachability_dynamic_imports_detected` |

`confidence` is `high` for a direct import with no dynamic imports seen, `medium` for one to three hops, and `low` for four or more hops or when dynamic imports were seen.

## Selecting analyzers

`--analyzers` uses the same [selector grammar](COMMANDS.md#selector-grammar) as the other component flags:

```bash
bomly scan --enrich --analyze --analyzers govulncheck            # only govulncheck
bomly scan --enrich --analyze --analyzers -govulncheck           # everything except govulncheck
bomly scan --enrich --analyze --analyzers govulncheck,jsreach    # these two
```

External analyzer plugins join the same selector once installed and enabled. See [Plugins](PLUGINS.md) and [How to implement an analyzer plugin](plugins/how-to-implement-analyzer.md).

## Limitations

| Limitation | Affects | Detail |
| --- | --- | --- |
| `unreachable` is not safe | All package-tier analyzers | See [above](#unreachable-is-not-safe) |
| Needs a buildable Go module | `govulncheck` | When the build fails, the status is `unknown` with one of the reasons below |
| Dynamic imports and runtime loaders are invisible | All | The result is a lower bound on what is reachable |
| Subpath imports count for the whole package | `jsreach`, `pyreach`, `jvmreach` | An advisory on one submodule marks the whole package reachable |
| Curated name maps | `pyreach`, `jvmreach` | A missing module-to-distribution or package-prefix entry can hide a direct import. Python falls back to name normalization; Java has no naming convention to fall back on |
| Workspace traversal reads declarations only | `jsreach`, `jvmreach` | `jsreach` follows npm and Yarn `workspaces` and `pnpm-workspace.yaml`; `jvmreach` follows Maven `<modules>` and Gradle `include(...)`. Computed workspace membership and Gradle composite builds are not followed |

`govulncheck` reason codes when the build fails:

| Reason | Cause |
| --- | --- |
| `missing-toolchain` | `go` is not on `PATH` |
| `no-go-packages` | No `.go` files, or build constraints exclude everything |
| `module-resolution-failed` | No `go.mod`, a missing `go.sum` entry, or a module download failed |
| `invalid-go-mod` | `go.mod` syntax error |
| `build-failed` | A compile error |
| `cancelled` | The run was cancelled or timed out |
| `runner-error` | Any other failure |

## See also

- [Auditors](AUDITORS.md) — every `--fail-on` value and how they combine
- [JSON schemas](SCHEMAS.md) — the full `reachability` object
- [How to implement an analyzer plugin](plugins/how-to-implement-analyzer.md) — add an analyzer for another language
