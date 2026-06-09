## How `cargo` resolves

`cargo-detector` is **hybrid (lockfile-first)**: it parses `Cargo.lock` directly when present, and falls back to `cargo metadata --format-version 1 --locked` when the lockfile is missing.

| Path | Strategy | Command |
| --- | --- | --- |
| `Cargo.lock` present | Lockfile parser | None |
| Lockfile missing | Build tool | `cargo metadata --format-version 1 --locked` |

The `--locked` flag is critical — it forbids Cargo from updating the lockfile, which keeps the exec path offline-safe.

## Network behavior

✅ Both paths are **offline-safe**. The lockfile parser reads a committed file; `cargo metadata --locked` uses cached registry data and does not fetch.

If you run on a fresh machine with no Cargo registry cache and no committed lockfile, `cargo metadata --locked` may fail rather than fetch — which is the safer trade-off.

## Prerequisites

- A committed `Cargo.lock` (strongly recommended), or `cargo` on `PATH` with a warm registry cache.
- `Cargo.toml` for evidence pattern matching.
- For workspaces: the root `Cargo.toml` declares `[workspace]`; every member crate is scanned.

## `--install-first`

`cargo` supports `--install-first`. When passed, Bomly runs `cargo fetch --locked` before resolving the graph, populating the registry cache.

⚠️ **`--install-first` downloads crates from crates.io** (or whatever sources `Cargo.toml` declares). The `--locked` flag forbids any lockfile changes.

```bash
bomly scan --install-first
```

### Customizing the install command

Append flags to `cargo fetch --locked` with repeatable `--install-arg`. Requires `--detectors cargo-detector`.

```bash
# Restrict to a specific target triple
bomly scan --install-first --detectors cargo-detector \
  --install-arg --target --install-arg x86_64-unknown-linux-gnu
```

## Examples

### Fix a direct vulnerability

```toml
[dependencies]
serde = "1.0.210"
```

`cargo update -p serde`. Re-scan.

### Pin a transitive vulnerability

Cargo supports `[patch.crates-io]` for transitive overrides:

```toml
[patch.crates-io]
openssl = { git = "https://github.com/sfackler/rust-openssl", tag = "openssl-v0.10.66" }
```

`cargo update`. Re-scan.

## Reachability

> **Not yet supported.** Bomly has no Rust reachability analyzer today. `--analyze` produces `not_applicable` for crates.

## Limitations

- **Feature flags** are recorded as metadata. Advisories that affect a specific feature still match the crate as a whole.
- **Target-specific dependencies** (`[target.'cfg(unix)'.dependencies]`) are all included; per-target reachability is not computed.
- **Workspace inheritance** (`workspace = true`) is resolved from the root `Cargo.toml`.
- **`build.rs` scripts** are not invoked.
