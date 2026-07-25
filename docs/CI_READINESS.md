# CI-Readiness Hints

Some CI failures have nothing to do with vulnerabilities. The lockfile was written by pnpm 11 while CI runs pnpm 9. `package.json` pins a package manager the lockfile does not match. An install policy such as pnpm's `minimumReleaseAge` rejects the fix version because it was published an hour ago.

Bomly reports these as **CI-readiness hints**: read-only observations about the package-manager setup around your project, so you learn "CI will fail even if the vulnerability is fixed" before you push.

## How to see them

Hints run on every `bomly scan`, `bomly explain`, and `bomly diff` of a local directory or Git target. They appear as ⚠ lines under the detection step:

```bash
bomly scan
```

```txt
✔ Detected Dependencies
  ⚠ pnpm  pnpm-lock.yaml is format version 9.0, which requires pnpm >= 9, but pnpm 8.15.4 is on PATH; CI cannot read this lockfile
```

Agents get the same hints through the MCP server, in the `diagnostics` array of every tool response, tagged with the `ci-readiness` stage:

```json
{
  "stage": "ci-readiness",
  "source": "pnpm",
  "message": "pnpm-workspace.yaml sets minimumReleaseAge=1440 (24h); versions published inside that window are rejected at install, so a freshly published fix version fails CI until it ages out"
}
```

Progress output needs a terminal, so on a CI runner (no TTY) add `-v` — hints are logged as warnings on the same channel:

```bash
bomly scan -v
```

At `-vv` you also see which binaries were probed and what versions they reported.

## What is checked

Node projects (npm, pnpm, Yarn, Bun) — the ecosystem where the manager, the lockfile format, and the install policy are three independently versioned things:

| Check | Example hint |
| --- | --- |
| Lockfile format newer than the manager on PATH | `pnpm-lock.yaml` is format 9.0, pnpm 8 is installed — CI cannot read the lockfile |
| Lockfile format older than the manager on PATH | `yarn.lock` is a v1 lockfile, Yarn 4 is installed — it migrates the file, so `--immutable` / `--frozen-lockfile` fails |
| Corepack pin vs. the manager on PATH | `packageManager: "pnpm@11.0.0"` while pnpm 9 is installed |
| Corepack pin vs. the committed lockfile | `packageManager: "yarn@4.1.0"` next to a `pnpm-lock.yaml` |
| `engines` constraints vs. PATH | `engines.node: ">=22"` while Node 20 is installed — installs fail wherever `engine-strict` is set |
| Install age gates | `minimumReleaseAge` in `pnpm-workspace.yaml`, `minimum-release-age` in `.npmrc` |
| Install date gates | `before=` in `.npmrc` |

Version comparisons are by major version, so a routine patch difference between your machine and the pin is not reported.

## Semantics and limits

- **Read-only and network-free.** Bomly reads `package.json`, lockfiles, `pnpm-workspace.yaml`, and `.npmrc`, and runs `<manager> --version` for managers already on `PATH`. It never installs anything and never contacts the network.
- **Never fails a scan.** Hints do not create findings, do not affect the exit code, and do not count as degraded coverage for baseline writes. They are advisory only.
- **PATH is a proxy for CI.** The comparison is against the tooling on the machine running Bomly. If your CI image pins different versions than your laptop, run Bomly in CI to get hints that reflect CI.
- **Corepack quiets the pin check.** With Corepack enabled, `pnpm --version` already reports the pinned version, so no mismatch is reported — which is the correct answer.
- **Unknown or unreadable inputs are skipped silently.** A malformed lockfile is the detectors' problem to report, not this check's.
- **Node only, for now.** Other ecosystems have the same class of problem (Gradle wrappers, Python resolver pins); they are not covered yet.

## Fixing what you see

| Hint | Typical fix |
| --- | --- |
| Lockfile requires a newer manager | Bump the manager in CI, or regenerate the lockfile with the version CI runs |
| Manager migrates the lockfile | Regenerate the lockfile with the manager CI runs and commit it |
| Corepack pin mismatch | Enable Corepack (`corepack enable`) so both machines use the pinned version |
| Pin disagrees with the lockfile | Delete the stale lockfile, or correct the `packageManager` pin |
| `engines` unsatisfied | Align the runtime version in CI with the constraint |
| Install age gate | Wait out the window, add the fixed version to the gate's exclude list, or lower the threshold for that dependency |
