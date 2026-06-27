# Troubleshooting

Common errors, what they mean, and how to resolve them. For exit-code semantics see [Exit codes](EXIT_CODES.md).

## "no detector chain produced a graph" (exit 3)

The selected detector chain could not produce graph data for at least one subproject.

**Most likely cause.** A native command Bomly needs is not on `PATH`, or the lockfile the native detector expects is missing.

Try in order:

1. Re-run with `-v` to see which subproject and which detector failed.
2. Confirm the package manager is installed: `go version`, `npm --version`, `mvn -v`, etc.
3. If a lockfile is missing, generate it (`npm install`, `go mod tidy`, `mvn dependency:tree`).
4. If you don't want native graphs for a subproject, allow Syft fallback by leaving `syft-detector` in the chain.

If you intentionally disabled Syft fallback (`--detectors -syft-detector`) and the native detector cannot proceed, exit 3 is expected.

## "invalid `--fail-on` value" (exit 4)

The token is not one of `any` / `low` / `medium` / `high` / `critical` / `reachable`. Tokens are case-insensitive; the error message lists the accepted set.

```bash
bomly scan --audit --fail-on critical    # correct
bomly scan --audit --fail-on severe      # exit 4
```

See [Auditors](AUDITORS.md#--fail-on) for the grammar.

## "--format sarif requires --audit" (exit 4)

SARIF is a findings format and only makes sense with an auditor. Add `--audit`:

```bash
bomly scan --enrich --audit --format sarif
```

## "--ref requires --url" (exit 4)

`--ref` is meaningful only when cloning a Git repository. For local paths, `cd` to the desired worktree.

## SARIF upload step shows zero results

The scan exited `0` with no findings: nothing matched `--fail-on` and your matchers produced no eligible vulnerabilities.

Check:

- You passed `--enrich` (without it there are no vulnerabilities).
- The matcher you expect actually ran: `bomly scan ... --enrich -v` shows matcher start/end logs.

## Enrichment is slow on first run

Expected. OSV and KEV are cached under `~/.bomly/cache/` after the first lookup. Subsequent runs hit the cache and complete in seconds.

To pre-warm the cache in CI, schedule a nightly enrichment run on `main`.

## Enrichment fails with rate-limit or network errors

Bomly degrades rather than aborts. A warning is logged; the scan still completes (exit 0 if no `--fail-on` matches). The cache is not poisoned by failed lookups.

To force-fail on missing enrichment data, combine `--enrich --audit --fail-on <severity>` — packages without resolved vulnerability data will simply not match `--fail-on`, but you can spot them with `-v` warnings.

## Cache looks stale

Delete the directory:

```bash
rm -rf ~/.bomly/cache                # Unix/macOS
Remove-Item -Recurse $env:USERPROFILE\.bomly\cache  # PowerShell
```

Per-matcher TTLs are listed in [Matchers](MATCHERS.md#cache).

## "ErrNotATerminal" when using `--interactive`

`--interactive` requires a TTY on **both** stdin and stderr. It refuses to run in CI pipes, GitHub Actions, or `tmux` sessions where stderr is captured.

In CI, use `--format text` (default) or `--json` instead.

## Container scan errors with "unauthorized"

Bomly uses your host's registry credentials. Confirm with:

```bash
docker pull <image-ref>
```

If `docker pull` works and `bomly scan --image <image-ref>` doesn't, file a bug with the credential helper you use (`docker-credential-*`).

## `bomly-lite` says "syft: command not found"

The lite binary shells out to external `syft` and `grype`. Install them:

```bash
# Anchore install scripts
curl -sSfL https://get.anchore.io/syft  | sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
```

Or switch to the full `bomly` binary (Syft and Grype linked in):

```bash
go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest
```

## "plugin protocol mismatch"

A plugin was built against a different version of Bomly's plugin SDK. Rebuild the plugin against the SDK version reported by `bomly version`, or pin the plugin tag to one matching your CLI.

## Diff shows packages that didn't change

`bomly diff` compares the resolved graph, not the manifest. A version-range update upstream can shift a transitive resolution without any manifest edit. Run `bomly explain <package>` on both sides to see where the new path came from.

## Reachability shows everything as `unknown`

Either you didn't pass `--analyze`, or the analyzer for the ecosystem isn't applicable.

- Reachability is opt-in. Add `--analyze`.
- Each ecosystem has its own analyzer (Go: `govulncheck`; JS/TS: `jsreach`; Python: `pyreach`; JVM: `jvmreach`). If your project's ecosystem isn't listed, status will stay `not_applicable`.

See [Reachability](REACHABILITY.md) for ecosystem coverage.

## Output looks garbled in CI logs

ANSI escapes are auto-stripped when stdout is not a TTY, but some CI runners report stdout as a TTY incorrectly. Force plain text:

```bash
NO_COLOR=1 bomly scan
```

## Need more detail

Re-run with `-v` (INFO) or `-vv` (DEBUG). DEBUG logs include exact subprocess command lines, cache keys, and per-package decisions, which is usually enough to file a useful bug report.

```bash
bomly scan --enrich -vv 2> bomly.log
```

Then open an issue with `bomly.log` attached.
