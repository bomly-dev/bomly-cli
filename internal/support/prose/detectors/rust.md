## Scan your Rust crate

Bomly's `cargo-detector` reads `Cargo.lock` (preferred) or falls back to `Cargo.toml` for libraries that do not commit a lockfile. It resolves crates.io coordinates with exact versions, dev-dependencies, build-dependencies, and target-specific dependencies.

```bash
bomly scan --path .
```

For a workspace, the `Cargo.toml` at the workspace root is the entry point; every member crate is scanned and consolidated.

## Prerequisites

- A committed `Cargo.lock` for full transitive coverage. The detector handles Cargo lockfile v3 and v4.
- For library crates that intentionally do not commit a lockfile, `Cargo.toml` is parsed for direct dependencies only; transitives are missing.
- No Cargo or `rustc` installation is required to scan.

## Examples

### Fix a direct vulnerability

Bump in `Cargo.toml`:

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

## Limitations

- **No reachability analyzer for Rust today.** `--reachability` produces `not_applicable` for crates.
- **Feature flags** are recorded as metadata. Advisories that affect a specific feature still match the crate as a whole.
- **Target-specific dependencies** (`[target.'cfg(unix)'.dependencies]`) are all included; per-target reachability is not computed.
- **Workspace inheritance** (`workspace = true`) is resolved from the root `Cargo.toml`.
- **`build.rs` scripts** are not invoked.
