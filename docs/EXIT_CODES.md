# Exit Codes

Bomly uses a small, stable set of exit codes so scripts and CI pipelines can branch on outcome without parsing output.

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | Success | Command completed; no `--fail-on` policy matched |
| 1 | Execution error | Unexpected failure (I/O, panic, plugin crash, internal error) |
| 2 | Policy violation | At least one finding matched `--fail-on` |
| 3 | Resolution failure | A required detector could not produce a graph (e.g. missing lockfile, malformed manifest) |
| 4 | Invalid input | A flag value, target, or config setting is invalid |

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
- `-o spdx-json=` (empty path after `=`).

Exit-4 errors describe the offending flag in the message and never produce partial output.

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
  *) echo "scan failed with $code"; exit 1 ;;
esac
```

## See also

- [Auditors](AUDITORS.md) — `--fail-on` and `--fail-on-scope` grammar
- [Troubleshooting](TROUBLESHOOTING.md) — what to try when you see exit 1 or 3
