# Exit codes

Bomly uses a small, fixed set of exit codes so scripts and CI pipelines can branch on the outcome without parsing output. This page is for anyone writing such a script.

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | Success | The command completed and no `--fail-on` policy matched |
| 1 | Execution error | An unexpected failure: I/O, a crash, a plugin crash, an internal error |
| 2 | Policy violation | At least one finding matched `--fail-on` |
| 3 | Resolution failure | A required detector could not build a graph, for example a missing lockfile or a malformed manifest |
| 4 | Invalid input | A flag value, target, or config setting is invalid |
| 5 | Nothing to evaluate | No project was found at the target, often because an `--ecosystems` or `--detectors` filter matched nothing |

## When each code is returned

### `0`: success

The scan, explain, or diff produced a result. If you passed `--audit --fail-on …`, no finding matched. This keeps CI green.

### `1`: execution error

Something unexpected went wrong. Examples: an external matcher process crashed, a SARIF write failed because the path was not writable, or Bomly hit an internal bug. Re-run with `-vv` for a debug log, and open an issue if it happens again.

### `2`: policy violation

At least one finding matched `--fail-on`. The graph and the findings are still printed; only the exit code differs from `0`. This is the code your CI should treat as a failed check.

```bash
bomly scan --enrich --audit --fail-on high
echo $?  # 2 if any high-or-above finding is present
```

### `3`: resolution failure

A detector that was needed for the target could not build a graph. Typical causes:

- the only detector left for a package manager cannot run, for example `npm` without a `package-lock.json` after you removed the Syft fallback with `--detectors -syft-detector`;
- a tool Bomly tried to run is not on `PATH`, for example `mvn` for the Maven detector;
- an SBOM input is corrupt.

Run with `-v` to see which project and detector failed.

### `4`: invalid input

A flag, target, or config value is malformed. Examples: `--fail-on xyz` (the message lists the accepted values), `--format sarif` without `--audit`, `--audit` without `--enrich`, `--ref` without `--url`, or `-o spdx=` with an empty path. The error names the offending flag, and no partial output is produced.

### `5`: nothing to evaluate

No project was found at the target, so there was nothing to scan, diff, or audit. This differs from `3`. Exit `3` means Bomly found a project but could not turn it into a graph. Exit `5` means it found none. Typical causes: an `--ecosystems` or `--detectors` filter that matches nothing in the target (for example `--ecosystems maven` on an npm-only repository), or a directory, ref, or image with no supported manifests. The message lists the active filters and the candidates it skipped; see [Troubleshooting](TROUBLESHOOTING.md#nothing-to-evaluate-exit-5).

No partial output is produced. If an empty target should pass in CI, treat `5` as success while still failing on `1`, `3`, and `4`.

## Recipes

In GitHub Actions, let a policy violation fail the job but still upload the SARIF file:

```yaml
- name: Scan
  run: bomly scan --enrich --audit --fail-on high --format sarif > bomly.sarif
- name: Upload SARIF
  if: success() || failure()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bomly.sarif
```

In a shell script, tell a policy failure apart from a real error:

```bash
bomly scan --enrich --audit --fail-on high
code=$?
case $code in
  0) echo "clean" ;;
  2) echo "policy violation"; exit 2 ;;
  5) echo "nothing to evaluate"; exit 0 ;;  # no supported project; treat as a pass
  *) echo "scan failed with $code"; exit 1 ;;
esac
```

## See also

- [Auditors](AUDITORS.md) — the `--fail-on` values
- [Troubleshooting](TROUBLESHOOTING.md) — what to try when you see exit 1, 3, or 5
