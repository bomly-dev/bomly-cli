# Exit Codes

Bomly uses a small, stable set of exit codes so scripts and CI pipelines can branch on outcome without parsing output.

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | Success | Command completed; no `--fail-on` policy matched |
| 1 | Execution error | Unexpected failure (I/O, panic, plugin crash, internal error) |
| 2 | Policy violation | At least one finding matched `--fail-on` |
| 3 | Resolution failure | A required detector could not produce a graph (e.g. missing lockfile, malformed manifest) |
| 4 | Invalid input | A flag value, target, or config setting is invalid |
| 5 | Nothing to evaluate | No subprojects/manifests were discovered for the target (often because an `--ecosystems`/`--detectors` filter matched nothing) |

## When each code is returned

### `0` — Success

The scan, explain, or diff produced a result. If you passed `--audit --fail-on …`, no finding matched. Use this to keep CI green.

### `1` — Execution error

Something unexpected went wrong. Examples:

- An external matcher process panicked.
- A SARIF write failed because the output path was unwritable.
- An internal invariant tripped.

Re-run with `-vv` for a debug log and file a bug if it reproduces.

### `2` — Policy violation

At least one finding matched the `--fail-on` constraint. The graph and the findings are still emitted; only the exit code differs from `0`. This is the code your CI should treat as a meaningful fail signal.

```bash
bomly scan --enrich --audit --fail-on high
echo $?  # 2 if any high-or-above finding is present
```

### `3` — Resolution failure

A detector that Bomly considered required for the scan target could not produce graph data. Typical causes:

- The selected detector chain has no fallback and the preferred detector cannot proceed (e.g. `npm-detector` without a `package-lock.json` and `--detectors -syft-detector`).
- A native command Bomly tried to run is not on `PATH` (e.g. `mvn` for the Maven native detector).
- An SBOM ingest input is corrupt.

Run with `-v` to see which subproject failed and which detector produced the error.

### `4` — Invalid input

A flag, target, or config value is malformed. Examples:

- `--fail-on xyz` (the message lists accepted values).
- `--format sarif` without `--audit`.
- `--ref` passed without `--url`.
- `-o spdx=` (empty path after `=`).

Exit-4 errors describe the offending flag in the message and never produce partial output.

### `5` — Nothing to evaluate

No subprojects were discovered for the target, so there was nothing to scan, diff, or audit. This is distinct from `3`: exit `3` means Bomly *found* a subproject but a detector could not turn it into a graph (a real failure), whereas exit `5` means none were found in the first place. Typical causes:

- An `--ecosystems` / `--detectors` filter that doesn't match anything in the target (e.g. `--ecosystems maven` against a pure-npm repo). The message lists the active filters.
- A target (directory, ref, or image) that contains no supported manifests at all.

No partial output is produced. CI wrappers that should pass when there is simply nothing applicable to evaluate can treat `5` as a neutral, non-failing outcome while still failing on `1`/`3`/`4`.

## Recipes

### GitHub Actions — fail on high vulnerabilities

```yaml
- name: Scan
  run: bomly scan --enrich --audit --fail-on high --format sarif > bomly.sarif
- name: Upload SARIF
  if: success() || failure()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bomly.sarif
```

A non-zero exit on policy violation fails the job; `if: success() || failure()` ensures the SARIF upload still runs.

### Shell — distinguish policy fail from real error

```bash
bomly scan --enrich --audit --fail-on high
code=$?
case $code in
  0) echo "clean" ;;
  2) echo "policy violation"; exit 2 ;;
  5) echo "nothing to evaluate"; exit 0 ;;  # no applicable manifests — treat as a pass
  *) echo "scan failed with $code"; exit 1 ;;
esac
```

## See also

- [Auditors](AUDITORS.md) — `--fail-on` grammar
- [Troubleshooting](TROUBLESHOOTING.md) — what to try when you see exit 1 or 3
