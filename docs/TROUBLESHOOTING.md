# Troubleshooting

This page lists the errors and surprises people hit most often, what each means, and how to fix it. For what each exit code means, see [Exit codes](EXIT_CODES.md).

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `no detector chain produced a graph` (exit 3) | A package manager is not on `PATH`, or a lockfile is missing | [Below](#no-detector-chain-produced-a-graph-exit-3) |
| `Nothing to evaluate` (exit 5) | No project was found at the target, or filters excluded it | [Below](#nothing-to-evaluate-exit-5) |
| `invalid --fail-on value` (exit 4) | A typo in the value | [Below](#invalid---fail-on-value-exit-4) |
| `--format sarif requires --audit` (exit 4) | SARIF needs findings | Add `--audit` (and `--enrich`) |
| `--audit requires --enrich` (exit 4) | Audit needs enrichment data | Add `--enrich` |
| `--ref requires --url` (exit 4) | `--ref` only applies to a cloned repository | Drop `--ref`, or add `--url` |
| SARIF upload shows zero results | The scan found nothing, often because `--enrich` was missing | [Below](#sarif-upload-shows-zero-results) |
| First enrichment is slow | Grype downloads its database once | [Below](#enrichment-is-slow-on-first-run) |
| Enrichment fails with network or rate-limit errors | A service was unavailable | [Below](#enrichment-fails-with-rate-limit-or-network-errors) |
| `--interactive` refuses to start | No terminal on stdin or stderr | [Below](#--interactive-refuses-to-start) |
| Container scan says `unauthorized` | Registry credentials are missing | [Below](#container-scan-errors-with-unauthorized) |
| `syft: command not found` | You run `bomly-lite` without Syft | [Below](#bomly-lite-says-syft-command-not-found) |
| `plugin protocol mismatch` | A plugin was built for another SDK version | [Below](#plugin-protocol-mismatch) |
| Reachability shows everything as `unknown` | `--analyze` missing, or no analyzer for the ecosystem | [Below](#reachability-shows-everything-as-unknown) |
| Output looks garbled in CI logs | The runner reports a terminal it does not have | `NO_COLOR=1 bomly scan` |

## "no detector chain produced a graph" (exit 3)

No detector could build a graph for at least one project. The usual causes are a package manager that is not on `PATH`, or a lockfile the detector expects that is missing. Try in order:

1. Re-run with `-v` to see which project and detector failed.
2. Check the package manager is installed: `go version`, `npm --version`, `mvn -v`.
3. If a lockfile is missing, generate it (`npm install`, `go mod tidy`, `mvn dependency:tree`).
4. To let Syft handle the project instead, keep `syft-detector` in the chain.

If you disabled the Syft fallback on purpose (`--detectors -syft-detector`) and the native detector cannot run, exit 3 is the expected result.

## "Nothing to evaluate" (exit 5)

The scan found no project to scan. The report says what was searched, which filters were active, every manifest candidate it saw, and why each was skipped:

```text
Nothing to evaluate: no subprojects discovered for execution target with the applied filters
  target: /home/me/monorepo
  search: target root only (no --recursive)
  manifest candidates found (depth <= 3) — all skipped: not scanned without --recursive
    - api/go.mod (gomod)
    - web/package.json (npm)
  hint: manifests exist in subdirectories (e.g. api); retry with --recursive
```

Each reason names the setting to change:

| Reason | What to do |
| --- | --- |
| `not scanned without --recursive` | The manifest is in a nested directory. Add `--recursive` (see [Monorepos](MONOREPOS.md)) |
| `below --max-depth N` | Raise `--max-depth`, or use `--max-depth 0` for no limit |
| `excluded by --exclude <pattern>` | Drop or narrow that `--exclude` pattern |
| `excluded by --ecosystems <list>` | The candidate's ecosystem is outside your `--ecosystems` selection |
| `detector filter excludes every <pm> detector (...)` | `--detectors` or `--exclude-detectors` removed every detector that could handle it |

The probe looks at most 3 levels below the target and lists at most 8 candidates.

A missing toolchain is a different failure. The manifest is found, and the scan fails at resolution with exit 3 and a message such as `subproject web (javascript/npm): no usable detector: npm-native not ready (npm not on PATH); npm not ready (no committed lockfile)`. Install the named tool, commit a lockfile, or select a detector that reads committed files.

## "invalid `--fail-on` value" (exit 4)

The value is not one of `any`, `low`, `medium`, `high`, `critical`, `reachable`, `exploitable`, or (for `bomly diff`) `source-change`. Values are case-insensitive, and the error message lists the accepted set.

```bash
bomly scan --enrich --audit --fail-on critical    # correct
bomly scan --enrich --audit --fail-on severe      # exit 4
```

See [Auditors](AUDITORS.md#--fail-on).

## SARIF upload shows zero results

The scan exited `0` with no findings. Check that you passed `--enrich` (without it there are no vulnerabilities to find), and that the matcher you expect ran: `bomly scan --enrich -v` logs each matcher's start and end.

## Enrichment is slow on first run

This is expected. The bundled Grype downloads its vulnerability database on first use, and matcher responses are cached under `~/.bomly/cache/`. Later runs read the cache and finish in seconds. In CI, cache that directory between runs, and schedule a nightly run on `main` to keep it warm. See [CI integration](CI_INTEGRATION.md#cache-enrichment-data).

## Enrichment fails with rate-limit or network errors

Bomly logs a warning and continues. The scan still completes, and failed lookups are not cached. Packages whose lookup failed have no vulnerability data, so they cannot match `--fail-on`; `-v` shows which ones were affected.

## Cache looks stale

Delete the cache directory:

```bash
rm -rf ~/.bomly/cache                                # Linux, macOS
Remove-Item -Recurse $env:USERPROFILE\.bomly\cache   # PowerShell
```

Cache lifetimes per matcher are listed in [Matchers](MATCHERS.md#cache).

## `--interactive` refuses to start

The interactive view needs a terminal on both stdin and stderr. It cannot run in CI pipes, GitHub Actions, or a `tmux` session that captures stderr. Use `--format text` (the default) or `--json` there instead.

## Container scan errors with "unauthorized"

Bomly uses your host's registry credentials. Check that a plain pull works:

```bash
docker pull <image-ref>
```

If `docker pull` works and `bomly scan --image <image-ref>` does not, open an issue naming the credential helper you use (`docker-credential-*`).

## `bomly-lite` says "syft: command not found"

The lite binary runs the `syft` and `grype` binaries on your `PATH`. Install them with Anchore's scripts:

```bash
curl -sSfL https://get.anchore.io/syft  | sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
```

Or switch to the full `bomly` binary, which has both built in. See [Installation](INSTALLATION.md#bomly-and-bomly-lite).

## "plugin protocol mismatch"

The plugin was built against a different version of Bomly's plugin SDK. Rebuild it against the SDK version that `bomly version` reports, or install a plugin release that matches your CLI.

## Diff shows packages that did not change

`bomly diff` compares the resolved graphs, not the manifests. A version-range update upstream can change a transitive resolution without any manifest edit. Run `bomly explain <package>` on both sides to see where the new path came from.

## Reachability shows everything as `unknown`

Either you did not pass `--analyze`, or no analyzer covers the ecosystem. Reachability is opt-in, so add `--analyze` (with `--enrich`). Each ecosystem has its own analyzer (Go: `govulncheck`; JavaScript and TypeScript: `jsreach`; Python: `pyreach`; JVM: `jvmreach`). If your project's ecosystem has no analyzer, every status stays `unknown`. See [Reachability](REACHABILITY.md).

## Output looks garbled in CI logs

Bomly turns off color codes when stdout is not a terminal, but some CI runners claim a terminal they do not have. Force plain output:

```bash
NO_COLOR=1 bomly scan
```

## Turn the startup logo on or off

`bomly --help` prints a static logo when stderr is an interactive terminal. Set `BOMLY_LOGO` to play a short animation instead, either a random one or a named variant (`reveal`, `rain`, `glitch`, or `slide`):

```bash
BOMLY_LOGO=1 bomly --help
BOMLY_LOGO=rain bomly --help
```

The animation is skipped when `BOMLY_NO_ANIMATION`, `CI`, or `BOMLY_QUIET` is set. `NO_COLOR` switches to a plain logo. When stderr is not a terminal, no logo is printed.

## Need more detail

Re-run with `-v` (info) or `-vv` (debug). Debug logs include subprocess commands, working directories, cache keys, per-package decisions, and the raw stderr of invoked package managers, analyzers, matchers, Git, Java, and plugins. Bomly cannot reliably remove secrets from other tools' output, so treat debug logs as sensitive. Info logs do not include raw subprocess output.

```bash
bomly scan --enrich -vv 2> bomly.log
```

Then open an issue with `bomly.log` attached.
