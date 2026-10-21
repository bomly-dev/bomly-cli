# CI-readiness warnings

Some CI failures have nothing to do with vulnerabilities. The lockfile was written by pnpm 11 while the project pins pnpm 9. `package.json` pins one package manager but the repository commits another's lockfile. An install policy such as pnpm's `minimumReleaseAge` rejects the fix version because it was published an hour ago.

Bomly reports these while it resolves your dependencies. This page is for anyone who sees one of these warnings and wants to know what it checks and how to fix it. The dependency graph itself is fine, which is why they are warnings and not errors. They tell you "CI will fail even after the vulnerability is fixed" before you push.

## What is checked, and how to fix it

The checks cover Node projects (npm, pnpm, Yarn, Bun), where the package manager, the lockfile format, and the install policy are three separately versioned things:

| Check | Code | Example | Typical fix |
| --- | --- | --- | --- |
| The pinned manager cannot read the lockfile format | `lockfile-format-mismatch` | `pnpm-lock.yaml` is format 9.0 and `packageManager` pins `pnpm@8.15.4` | Raise the pin, or regenerate the lockfile with the pinned version |
| The pinned manager would rewrite the lockfile | `lockfile-format-mismatch` | `yarn.lock` is a v1 lockfile and `packageManager` pins `yarn@4.1.0`, so `--immutable` or `--frozen-lockfile` fails | Regenerate the lockfile with the pinned manager and commit it |
| The pinned manager does not read the committed lockfile | `lockfile-unsupported` | `packageManager: "yarn@4.1.0"` next to a `pnpm-lock.yaml` | Delete the stale lockfile, or correct the `packageManager` pin |
| `engines` contradicts the pin | `engines-constraint-mismatch` | `engines.pnpm: ">=10"` while `packageManager` pins `pnpm@9.15.0` | Align the constraint and the pin |
| An install age gate | `install-policy-gate` | pnpm's `minimumReleaseAge` (minutes) in `pnpm-workspace.yaml`, npm's `min-release-age` (days) in `.npmrc` | Wait out the window, add the fixed version to the gate's exclude list, or lower the threshold for that dependency |
| An install date gate | `install-policy-gate` | npm's `before=` in `.npmrc` | Move the date, or exclude the dependency |

Only the manager that will run the install is consulted: the `packageManager` pin when the project declares one, otherwise the manager the detector used. Each manager's install gate lives in its own file and its own units, and the others ignore it. Lockfile compatibility follows the same rule: npm documents `yarn.lock` as an install input, and Bun converts `pnpm-lock.yaml`, so neither combination is reported. A combination no manager documents is not reported either.

Versions are compared by major version, so a routine patch difference is never reported.

## Where the warnings appear

| Surface | Where to look |
| --- | --- |
| Progress output (default, needs a terminal) | A `⚠` line under "Detected Dependencies" |
| Text and Markdown reports | Above the summary, so `-q` and non-terminal CI runs still see them |
| JSON | The document's top-level `warnings` collection |
| Logs | At `-v` |
| MCP | The `diagnostics` array under the `detect` stage |

In JSON, `type` and `code` are stable. `message` is written for people and may be reworded, so match on the first two:

```json
{
  "warnings": [{
    "type": "package-manager",
    "code": "install-policy-gate",
    "source": "pnpm",
    "manifest": "pnpm-workspace.yaml",
    "message": "pnpm-workspace.yaml sets minimumReleaseAge=1440 (24h); versions published inside that window are rejected at install, so a freshly published fix version fails CI until it ages out"
  }]
}
```

`type` separates advice from reduced coverage. `package-manager` means the graph is complete and the warning is about your project's configuration. `fallback` and `resolution-failure` mean detection itself was degraded, so findings may be missing. See [Architecture](ARCHITECTURE.md).

## Rules and limits

- **Read-only, no network.** Bomly reads only committed files: `package.json`, the lockfile the detector already parsed, `pnpm-workspace.yaml`, and `.npmrc`. It never runs the package manager, because `pnpm` and `yarn` on `PATH` are often Corepack shims that download the pinned manager on first use, and that would put a network call in a plain scan.
- **The repository is the source of truth, not your `PATH`.** CI installs with what the repository declares, so that is what Bomly compares. A mismatch between your machine and the pin is not reported, and a project that pins nothing gets no version checks.
- **Never fails a scan.** These warnings create no findings and do not change the exit code. They do not block the `bomly baseline` commands either.
- **Unreadable inputs are skipped.** A malformed lockfile is the detector's error to report, not this check's.
- **Node only, for now.** Other ecosystems have the same class of problem (Gradle wrappers, Python resolver pins) and are not covered yet.
