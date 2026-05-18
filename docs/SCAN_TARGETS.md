# Scan Targets

Bomly resolves dependencies from four kinds of input. Each subcommand (`scan`, `explain`, `diff`) accepts the same target flags.

| Target | Flag | Default |
| --- | --- | --- |
| Local directory | `--path <dir>` | Current working directory |
| Git repository | `--url <repo>` (with optional `--ref`) | — |
| Container image | `--container <ref>` | — |
| Existing SBOM | `--sbom --path <file>` | — |

Exactly one target type per run. Combining `--container` with `--url`, or passing `--ref` without `--url`, is rejected with exit 4.

## Local directory — `--path`

The default. Scans every subproject Bomly finds beneath the path.

```bash
bomly scan                       # scan current directory
bomly scan --path ./services/api # scan a sub-tree
bomly scan --path /tmp/extract   # scan an arbitrary tree
```

Discovery is recursive. Every directory containing recognized evidence (a lockfile, a manifest, a workflow file) becomes a subproject. Bomly consolidates them into a single graph.

There is no project-root concept: pointing at a monorepo root scans every workspace in one pass.

## Git repository — `--url` and `--ref`

Clone-then-scan, all in one step.

```bash
bomly scan --url https://github.com/example/repo
bomly scan --url https://github.com/example/repo --ref v1.2.0
bomly scan --url https://github.com/example/repo --ref main
```

The clone goes to a temporary directory and is removed after the scan. Credentials come from your local Git config (HTTPS via the credential helper; SSH via `~/.ssh`). Bomly does not store or log credentials.

`--ref` accepts any value `git checkout` accepts: branch, tag, commit SHA.

## Container image — `--container`

Pulls and scans an image by reference. Native detectors that work on lockfile contents inside layers still run; everything else falls through to Syft.

```bash
bomly scan --container ghcr.io/example/app:latest
bomly scan --container alpine:3.20
bomly scan --container <digest>
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
| `--container` alone | Yes | Pulls and scans the image |
| `--sbom` + `--path` | Yes | Ingests the SBOM file |
| `--sbom` + `--container` | No | Exit 4 |
| `--sbom` + `--url` | No | Exit 4 |
| `--ref` without `--url` | No | Exit 4 |
| `--container` + `--url` | No | Exit 4 |

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
