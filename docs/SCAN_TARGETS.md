# Scan targets

This page lists the four kinds of input Bomly can scan and the flags that select them. Read it when you want to scan something other than the current directory. `scan`, `explain`, and `diff` all accept these flags; `diff` takes a base and a head target instead of one.

| Target | Flag | Default |
| --- | --- | --- |
| Local directory | `--path <dir>` | Current working directory |
| Git repository | `--url <repo>` (with optional `--ref`) | — |
| Container image | `--image <ref>` | — |
| Existing SBOM | `--sbom --path <file>` | — |

Each run takes exactly one target type. The [combinations table](#combinations) at the end lists what is rejected.

> `--container` is a deprecated alias for `--image`. It still works, but it is hidden from `--help` and prints a notice. Use `--image`.

## Local directory: `--path`

This is the default. Bomly scans the projects it finds at the path.

```bash
bomly scan                       # scan the current directory
bomly scan --path ./services/api # scan a sub-tree
bomly scan --path /tmp/extract   # scan any directory
```

By default Bomly looks only at the target directory itself. Every package manager with evidence there (a lockfile, a manifest, or a workflow file) becomes a subproject. Workspace-aware package managers (npm, pnpm, and yarn workspaces, Maven reactors, Gradle builds, Cargo workspaces) also expand their own nested modules from the root manifest.

To scan independent projects in nested directories, add `--recursive`. [Monorepos](MONOREPOS.md) explains recursive discovery, depth and exclude rules, and how subprojects and modules appear in the output.

## Git repository: `--url` and `--ref`

Bomly clones the repository into a temporary directory, scans it, and deletes the clone.

```bash
bomly scan --url https://github.com/example/repo
bomly scan --url https://github.com/example/repo --ref v1.2.0
bomly scan --url https://github.com/example/repo --ref main
```

`--ref` accepts anything `git checkout` accepts: a branch, a tag, or a commit SHA. Credentials come from your local Git setup (the credential helper for HTTPS, `~/.ssh` for SSH). Bomly does not store or log them.

Bomly does not fetch submodules or Git LFS objects. Checked-out LFS pointer files are scanned as ordinary files. Clone time and checkout size are capped; the limits are listed in [Security and trust boundaries](SECURITY.md#files-and-resource-limits).

## Container image: `--image`

Bomly pulls the image and scans it. Native detectors still read the lockfiles they find inside the image layers. Everything else, including operating-system packages, goes through Syft.

```bash
bomly scan --image ghcr.io/example/app:latest
bomly scan --image alpine:3.20
bomly scan --image ghcr.io/example/app@sha256:<digest>   # pin by digest
```

Registry credentials come from your host: `~/.docker/config.json`, the Docker credential helpers, and `DOCKER_CONFIG` are all honored. Private images work once you have run `docker login` for the registry.

## Existing SBOM: `--sbom`

Bomly reads the file as an SBOM and skips ecosystem detection.

```bash
bomly scan --sbom --path ./vendor.spdx.json
bomly scan --sbom --path ./build/sbom.cdx.json
```

SPDX 2.3 JSON and CycloneDX 1.4 to 1.7 JSON are detected automatically. Any other format is rejected. Use this when:

- a previous CI step already produced an SBOM and you want to audit it;
- a vendor sent you an SBOM and you want to check it against your policy;
- you want to test output without re-running a slow detector.

An ingested SBOM looks like a normal scan with one difference. SBOMs do not carry Bomly's runtime and development split, so dependencies keep the relationship the SBOM recorded (here `required`) and count as `unscoped`:

```text
✓ 69 packages in 1 manifest   (1 direct, 68 transitive · runtime 0, dev 0, unscoped 69)

Top-level dependencies
  NAME      VERSION   LICENSE   SCOPE      VULNS
  express   4.21.2    MIT       required   -
```

See [SBOM formats](SBOM.md) for what Bomly reads and writes, and [SBOM field reference](SBOM_REFERENCE.md) for how each field is mapped.

## Combinations

| Combination | Allowed | Note |
| --- | --- | --- |
| `--path` alone | Yes | Default; scans the directory |
| `--url` + `--ref` | Yes | Checks out `ref` after the clone |
| `--image` alone | Yes | Pulls and scans the image |
| `--sbom` + `--path` | Yes | Reads the SBOM file |
| `--sbom` + `--image` | No | Exit 4 |
| `--sbom` + `--url` | No | Exit 4 |
| `--ref` without `--url` | No | Exit 4 |
| `--image` + `--url` | No | Exit 4 |
| `--recursive` + `--path` or `--url` | Yes | Walks nested directories |
| `--recursive` + `--image` | No | Exit 4 |
| `--recursive` + `--sbom` | No | Exit 4 |
| `--max-depth` or `--exclude` without `--recursive` | No | Exit 4 |

Whatever the target, the same pipeline runs afterwards: detect, consolidate, and optionally enrich, analyze, and audit. See [Architecture](ARCHITECTURE.md).

## See also

- [Monorepos](MONOREPOS.md) — recursive discovery, subprojects, and modules
- [Detectors](DETECTORS.md) — what runs on a local source tree
- [Network and privacy](NETWORK.md) — which targets reach the network
- [Config reference](CONFIG_REFERENCE.md) — how to set defaults for target flags
