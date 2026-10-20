# Monorepos

This page explains how Bomly scans a directory tree that holds more than one project: how `--recursive` finds nested projects, which directories it skips, and how nested projects and workspace modules appear in the output. Read it when one scan should cover a whole monorepo.

## Quick start

Run from the monorepo root:

```bash
bomly scan --recursive                          # walk 3 levels deep (default)
bomly scan --recursive --max-depth 1            # direct children only
bomly scan --recursive --max-depth 0            # no depth limit
bomly scan --recursive --exclude "fixtures/*"   # skip a subtree
bomly scan --recursive --exclude dist,examples  # repeatable, comma-separated
```

`--recursive` works with `--path` and `--url` targets. `--image` and `--sbom` scans reject it with exit 4.

## Two kinds of nesting

Bomly distinguishes two ways a project can sit inside another:

| Term | Meaning | Found by |
| --- | --- | --- |
| **Subproject** | An independent project in a nested directory, with its own detector run | `--recursive` |
| **Module** | A member that the package manager itself resolves under one root manifest: a Maven reactor module, an npm, pnpm, or yarn workspace member, a Cargo workspace member | The root manifest, with or without `--recursive` |

The [Glossary](GLOSSARY.md) carries the one-line definitions.

## What `--recursive` does

Bomly walks the directories below the scan root and creates a subproject for every directory that holds recognized evidence: a lockfile, a manifest, or a workflow file. All subprojects are consolidated into one graph, so one scan at the root covers every project.

The report shows the structure it found:

```text
✓ 78 packages in 2 manifests   (2 direct, 76 transitive · runtime 78, dev 0)
  ├─ api (subproject, npm)
  │  └─ demo — 68 packages [package-lock.json]
  └─ web (subproject, npm)
     └─ demo — 69 packages [package-lock.json]

Top-level dependencies
  NAME      VERSION   LICENSE   SCOPE     VULNS
  express   4.19.2    MIT       runtime   -
  express   4.21.2    MIT       runtime   -
```

A package appears twice when two subprojects pin different versions. Each version is its own package with its own package URL (PURL).

### Depth: `--max-depth`

Depth counts from the scan root. The root is depth 0 and a direct child is depth 1. Directories deeper than `--max-depth` are not visited. The default is `3`. `--max-depth 0` removes the limit. The flag requires `--recursive`.

### Excludes: `--exclude`

`--exclude` adds glob patterns on top of the built-in ignore rules. A matching directory and everything under it is skipped.

| Pattern | Matches against | Example |
| --- | --- | --- |
| Contains `/` | The directory path relative to the scan root | `--exclude "apps/*"` skips every direct child of `apps/`; `--exclude apps/api` skips that one directory |
| No `/` | The directory name at any depth | `--exclude dist` skips every `dist/` directory |

Patterns use Go `path.Match` syntax (`*`, `?`, `[...]`). `**` is not supported. The flag is repeatable, accepts comma-separated values, and requires `--recursive`.

### Built-in ignore rules

The walk never enters:

- directories whose name starts with `.` (`.git`, `.venv`, `.idea`, and so on); GitHub Actions workflows are still detected because their evidence is matched from the parent directory;
- `node_modules` and `vendor`, which hold third-party code;
- `target`, `build`, and `dist`, which are build outputs that often contain copied manifests;
- `__pycache__`, and any directory that contains a `pyvenv.cfg` file (a Python virtual environment).

Each detector declares the ignore rules for its own ecosystem, so external [detector plugins](PLUGINS.md) add their own the same way. Symlinked directories are not followed. Only the scan root itself is resolved if it is a symlink.

### Workspace roots are not counted twice

Some package managers resolve their nested modules from the root manifest. When Bomly finds such a root, it does not create separate subprojects for that package manager's nested manifests below it. The root's detector already covers them.

| Pruned below an ancestor root | Never pruned |
| --- | --- |
| maven (reactor modules), gradle (subprojects), npm, pnpm, and yarn (workspaces), cargo (workspace members), sbt (aggregated builds), mix (umbrella apps) | gomod, pip, pipenv, poetry, uv, pdm, bundler, composer, nuget, pub, cocoapods, swiftpm, conan, github-actions |

A nested `go.mod` is an independent Go module, so every nested Go module becomes its own subproject (`go.work` workspaces are scanned per module too). Pruning is per package manager: a Maven root does not hide a nested `requirements.txt`. Each detector declares whether it expands modules itself, so external detector plugins can opt in to pruning as well.

## Subprojects and modules in the output

The npm, pnpm, cargo, maven, and gradle detectors write **one manifest entry per module** next to the root manifest, for example `apps/web/package.json`, `crates/api/Cargo.toml`, `core/pom.xml`, or `app/build.gradle`. Each entry carries the dependencies reachable from that module. A virtual Cargo workspace root writes member entries only. Detectors without per-module output (sbt, mix, yarn classic, pub, and the node native detectors) keep one merged root manifest.

Every view derives the same hierarchy from the `subproject` and `path` fields on each manifest. There are no extra JSON fields.

| View | How nesting shows |
| --- | --- |
| Text report | A grouped manifest tree |
| Interactive TUI | Subproject and module nodes on the Components tab |
| Markdown | A Location column on the manifest table |
| JSON | A manifest whose directory sits below its `subproject` directory is a module manifest |
| MCP summary | `subprojects` and `modules` counts |

### Gradle limits

- Subprojects are read from the literal `include(...)` declarations in the settings script, and from literal `project("...").projectDir = file("...")` overrides. Includes built in loops, from variables, or by convention plugins are not evaluated.
- Composite builds (`includeBuild`) are not expanded. An included build's dependencies do not appear in the scan.
- If the multi-project dependency report fails (for example, a settings entry names a project the build no longer has), the scan falls back to the root project only and logs a warning. Module dependencies are then absent rather than partly wrong. A `--scope` restriction still applies to the fallback.

## When nothing is found

A scan that finds no subprojects exits 5 and prints what it searched and why each candidate was skipped. [Troubleshooting](TROUBLESHOOTING.md#nothing-to-evaluate-exit-5) lists the reasons and the flag to change for each.

## See also

- [Scan targets](SCAN_TARGETS.md) — directories, Git repositories, images, SBOMs
- [Detectors](DETECTORS.md) — per-ecosystem detectors and what they read
- [Config reference](CONFIG_REFERENCE.md) — `recursive`, `max_depth`, and `exclude` config keys
