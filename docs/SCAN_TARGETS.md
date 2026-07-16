# Scan Targets

Bomly resolves dependencies from four kinds of input. Each subcommand (`scan`, `explain`, `diff`) accepts the same target flags.

| Target | Flag | Default |
| --- | --- | --- |
| Local directory | `--path <dir>` | Current working directory |
| Git repository | `--url <repo>` (with optional `--ref`) | — |
| Container image | `--image <ref>` | — |
| Existing SBOM | `--sbom --path <file>` | — |

Exactly one target type per run. Combining `--image` with `--url`, or passing `--ref` without `--url`, is rejected with exit 4.

> `--container` is a deprecated alias for `--image`. It still works but is hidden from `--help` and prints a deprecation notice; prefer `--image`.

## Local directory — `--path`

The default. Scans the subprojects Bomly finds at the path.

```bash
bomly scan                       # scan current directory
bomly scan --path ./services/api # scan a sub-tree
bomly scan --path /tmp/extract   # scan an arbitrary tree
```

By default, discovery inspects only the target directory itself: every package manager with recognized evidence there (a lockfile, a manifest, a workflow file) becomes a subproject, and workspace-aware package managers (npm/pnpm/yarn workspaces, Maven reactors, Gradle builds, Cargo workspaces) expand their own nested modules from the root manifest. To also discover independent projects in nested directories, use `--recursive`.

## Recursive discovery — `--recursive`

`--recursive` walks the directory tree below the scan root and plans a subproject for every directory with recognized manifest evidence. Bomly consolidates them all into a single graph, so pointing at a monorepo root scans every project in one pass.

```bash
bomly scan --recursive                          # walk 3 levels deep (default)
bomly scan --recursive --max-depth 1            # direct children only
bomly scan --recursive --max-depth 0            # no depth limit
bomly scan --recursive --exclude "fixtures/*"   # skip a subtree
bomly scan --recursive --exclude dist,examples  # repeatable / comma-separated
```

It works with `--path` and `--url` targets. `--image` and `--sbom` scans do not use directory discovery and reject `--recursive` with exit 4.

### Depth — `--max-depth`

Depth is counted from the scan root: the root itself is depth 0 and a direct child is depth 1. Directories at depths beyond `--max-depth` are not visited. The default is `3`; `--max-depth 0` removes the limit. `--max-depth` requires `--recursive`.

### Excludes — `--exclude`

`--exclude` adds glob patterns on top of the built-in ignore rules. Matching directories and everything beneath them are skipped.

- A pattern containing `/` matches against the directory's path relative to the scan root: `--exclude "apps/*"` skips every direct child of `apps/`, `--exclude apps/api` skips exactly that directory.
- A pattern without `/` matches against the directory basename at any depth: `--exclude dist` skips every `dist/` directory in the tree.
- Patterns use Go `path.Match` syntax (`*`, `?`, `[...]`). `**` is not supported.
- The flag is repeatable and accepts comma-separated values. It requires `--recursive`.

### Built-in ignore rules

The walk never descends into:

- directories whose name starts with `.` (`.git`, `.venv`, `.idea`, …) — GitHub Actions workflows are still detected because their evidence is matched from the parent directory
- `node_modules`, `vendor` — third-party and vendored dependencies
- `target`, `build`, `dist` — build outputs that commonly contain copied manifests
- `__pycache__`, and any directory containing a `pyvenv.cfg` file (Python virtualenvs)

These rules are declared by the detectors themselves (each detector owns its ecosystem's ignore list), so external [detector plugins](PLUGINS.md) contribute additional ignored directories the same way built-ins do.

Symlinked directories are not followed; only the scan root itself is resolved if it is a symlink.

### Workspace roots are not double-counted

When a package manager whose detector natively expands nested modules is detected at an ancestor directory, nested manifests for that same package manager are pruned — the ancestor's detector already resolves them:

| Pruned below an ancestor root | Never pruned |
| --- | --- |
| maven (reactor modules), gradle (subprojects), npm / pnpm / yarn (workspaces), cargo (workspace members), sbt (aggregated builds), mix (umbrella apps) | gomod, pip / pipenv / poetry / uv / pdm, bundler, composer, nuget, pub, cocoapods, swiftpm, conan, github-actions, … |

A nested `go.mod` is an independent Go module by language semantics, so every nested Go module becomes its own subproject (`go.work` workspaces are also scanned per-module). Pruning is per package manager: a Maven root does not hide a nested `requirements.txt`.

Like the ignore rules, multi-module expansion is declared by each detector (`sdk.PackageManagerSupport.MultiModule`), so external detector plugins can opt their package manager into pruning.

## Subprojects and modules in scan output

Scan output distinguishes two kinds of nesting:

- A **subproject** is an independently discovered nested directory (its own detector run) — what `--recursive` finds.
- A **module** is a member the package manager natively resolves under one root manifest: a Maven reactor module, an npm/pnpm workspace member, a Cargo workspace member.

The npm, pnpm, cargo, maven, and gradle detectors emit **one manifest entry per module** — `apps/web/package.json`, `crates/api/Cargo.toml`, `core/pom.xml`, `app/build.gradle` — alongside the root manifest, each carrying the module's reachable dependency subtree (a virtual Cargo workspace root emits member entries only). Detectors without per-module emission (sbt, mix, yarn classic, pub, and the node *native* detectors) keep one merged root manifest.

Every view derives the same hierarchy from the manifests' `subproject` and `path` fields — no extra JSON fields: the interactive components tab shows subproject and module nodes with their manifests, the text report renders a grouped manifest tree, the markdown manifest table carries a Location column, and the MCP compact summary reports `subprojects`/`modules` counts. JSON consumers can group rows the same way: a manifest whose directory sits below its `subproject` directory is a module manifest.

## Git repository — `--url` and `--ref`

Clone-then-scan, all in one step.

```bash
bomly scan --url https://github.com/example/repo
bomly scan --url https://github.com/example/repo --ref v1.2.0
bomly scan --url https://github.com/example/repo --ref main
```

The clone goes to a temporary directory and is removed after the scan. Credentials come from your local Git config (HTTPS via the credential helper; SSH via `~/.ssh`). Bomly does not store or log credentials.

`--ref` accepts any value `git checkout` accepts: branch, tag, commit SHA.

## Container image — `--image`

Pulls and scans an image by reference. Native detectors that work on lockfile contents inside layers still run; everything else falls through to Syft.

```bash
bomly scan --image ghcr.io/example/app:latest
bomly scan --image alpine:3.20
bomly scan --image <digest>
```

Registry credentials come from your host: `~/.docker/config.json`, the Docker credential helpers, and `DOCKER_CONFIG` are all honored.

## Existing SBOM — `--sbom`

Treat a file as an SBOM input and skip ecosystem detection.

```bash
bomly scan --sbom --path ./vendor.spdx.json
bomly scan --sbom --path ./build/sbom.cdx.json
```

SPDX 2.3 JSON and CycloneDX 1.6 JSON are auto-detected. Useful when:

- You produced an SBOM in a previous CI step and want to audit it.
- A vendor sent you an SBOM and you want to evaluate it against your policy.
- You're testing detector output without re-running the heavy detector.

See [SBOM formats](SBOM.md) for the format comparison.

## Combinations

| Combination | Allowed | Note |
| --- | --- | --- |
| `--path` alone | Yes | Default; scans the directory |
| `--url` + `--ref` | Yes | Checks out `ref` after clone |
| `--image` alone | Yes | Pulls and scans the image |
| `--sbom` + `--path` | Yes | Ingests the SBOM file |
| `--sbom` + `--image` | No | Exit 4 |
| `--sbom` + `--url` | No | Exit 4 |
| `--ref` without `--url` | No | Exit 4 |
| `--image` + `--url` | No | Exit 4 |
| `--recursive` + `--path` or `--url` | Yes | Walks nested directories |
| `--recursive` + `--image` | No | Exit 4 |
| `--recursive` + `--sbom` | No | Exit 4 |
| `--max-depth` / `--exclude` without `--recursive` | No | Exit 4 |

## What runs after target resolution

The same pipeline runs regardless of target type:

1. Discover subprojects (no-op for SBOM ingest).
2. Run detector chains.
3. Consolidate the graph.
4. (Optional) Enrich with matchers — `--enrich`.
5. (Optional) Evaluate auditors — `--audit`.
6. Render output.

See [Architecture](ARCHITECTURE.md) for the full pipeline diagram.

## See also

- [Detectors](DETECTORS.md) — what runs on a local source tree
- [SBOM formats](SBOM.md) — SPDX vs. CycloneDX
- [Configuration](CONFIG_REFERENCE.md) — how to set defaults for target flags
