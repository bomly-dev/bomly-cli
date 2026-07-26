# CI-Readiness Warnings

Some CI failures have nothing to do with vulnerabilities. The lockfile was written by pnpm 11 while the project pins pnpm 9. `package.json` pins one package manager but the repository commits another's lockfile. An install policy such as pnpm's `minimumReleaseAge` rejects the fix version because it was published an hour ago.

Bomly reports these while it resolves your dependencies. The graph itself is fine — that is why these are warnings, not errors — but the project as committed will trip up an install elsewhere, so you learn "CI will fail even if the vulnerability is fixed" before you push.

## What is checked

Node projects (npm, pnpm, Yarn, Bun), where the manager, the lockfile format, and the install policy are three independently versioned things:

| Check | Example | Code |
| --- | --- | --- |
| Pinned manager cannot read the lockfile format | `pnpm-lock.yaml` is format 9.0, `packageManager` pins `pnpm@8.15.4` | `lockfile-format-mismatch` |
| Pinned manager migrates the lockfile format | `yarn.lock` is a v1 lockfile, `packageManager` pins `yarn@4.1.0` — it rewrites the file, so `--immutable` / `--frozen-lockfile` fails | `lockfile-format-mismatch` |
| Pinned manager does not read the committed lockfile | `packageManager: "yarn@4.1.0"` next to a `pnpm-lock.yaml` | `lockfile-unsupported` |
| `engines` contradicts the pin | `engines.pnpm: ">=10"` while `packageManager` pins `pnpm@9.15.0` | `engines-constraint-mismatch` |
| Install age gate | pnpm's `minimumReleaseAge` (minutes) in `pnpm-workspace.yaml`, npm's `min-release-age` (days) in `.npmrc` | `install-policy-gate` |
| Install date gate | npm's `before=` in `.npmrc` | `install-policy-gate` |

Each manager's install gate lives in its own file, under its own key, in its own units, and is ignored by the others, so only the manager that will actually run the install is consulted — the `packageManager` pin when the project declares one, otherwise the manager the detector used. Lockfile interoperability is modelled the same way: npm documents `yarn.lock` as install input, and Bun converts `pnpm-lock.yaml`, so neither combination is reported. Combinations no manager documents either way stay silent rather than guess.

Version comparisons are by major version, so a routine patch difference is never reported.

## Where they show up

Every detection warning travels the same way, so these reach every surface rather than only the live progress output:

**Progress** (default, needs a terminal):

```txt
✔ Detected Dependencies
  ⚠ pnpm  pnpm-lock.yaml is format version 6.0, written by pnpm 8.x or older, but package.json pins pnpm@11.0.0; …
```

**The report itself**, above the summary — so `-q` and non-terminal CI runs still see them, in both text and Markdown output.

**JSON**, in the document's top-level `warnings` collection, alongside the other
detection warnings. `type` and `code` are stable; `message` is written for humans
and may be reworded, so match on those:

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

`type` is what separates advice from degraded coverage. `package-manager` means
the graph is complete and the warning is about your project's configuration;
`fallback` and `resolution-failure` mean detection itself degraded, so findings
may be missing. See [Architecture](ARCHITECTURE.md) for the full list.

**Logs** at `-v`, and **MCP** tool responses, in the `diagnostics` array under the `detect` stage.

## Semantics and limits

- **Read-only and network-free.** Only committed files are read: `package.json`, the lockfile the detector already parsed, `pnpm-workspace.yaml`, and `.npmrc`. No package manager is executed. That is deliberate: `pnpm` and `yarn` on `PATH` are frequently Corepack shims, and running even `--version` can download the pinned manager on demand, which would put a network call in a plain scan.
- **The repository is the source of truth, not your `PATH`.** What CI installs with is what the repository declares, so that is what Bomly compares. The trade-off is that a mismatch between your machine and the pin is not reported — and a project that pins nothing gets no version checks at all.
- **Never fails a scan.** These warnings create no findings and do not affect the exit code. Because they carry the `package-manager` type, they also do not count as degraded coverage when `bomly baseline` decides whether the run was complete enough to record.
- **Unreadable or unrecognized inputs are skipped silently.** A malformed lockfile is the detector's error to report, not this check's.
- **Node only, for now.** Other ecosystems have the same class of problem (Gradle wrappers, Python resolver pins); they are not covered yet.

## Fixing what you see

| Warning | Typical fix |
| --- | --- |
| Pinned manager cannot read the lockfile | Bump the pin, or regenerate the lockfile with the pinned version |
| Pinned manager migrates the lockfile | Regenerate the lockfile with the pinned manager and commit it |
| Pin disagrees with the lockfile | Delete the stale lockfile, or correct the `packageManager` pin |
| `engines` contradicts the pin | Align the constraint and the pin |
| Install age or date gate | Wait out the window, add the fixed version to the gate's exclude list, or lower the threshold for that dependency |
