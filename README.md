# Bomly

**Dependency intelligence for developers and security teams.**

Bomly scans your projects for dependencies, generates SBOMs, audits for vulnerabilities, explains transitive paths, and diffs dependency state across Git refs — all from a single CLI.

---

## Features

- **Multi-ecosystem scanning** — npm, Maven, Gradle, Go, Python, and 30+ Syft-backed ecosystems
- **Vulnerability auditing** — OSV and Grype enrichment with CISA KEV flagging via `--audit`
- **SBOM generation** — SPDX 2.3 and CycloneDX output
- **Dependency explanation** — `bomly why <package>` traces introduction paths
- **Dependency diffing** — `bomly diff` compares dependency state across Git refs
- **Plugin extensibility** — executable plugins with a versioned JSON envelope protocol
- **CI-friendly** — JSON, SARIF, and structured output formats with `--fail-on` exit codes

---

## Quick Start

```bash
# Scan the current directory
bomly scan

# Generate an SPDX SBOM
bomly scan -o spdx-json

# Audit for vulnerabilities
bomly scan --audit

# Explain why a package is in your dependency tree
bomly why lodash

# Diff dependencies between Git refs
bomly diff --base main --head feature-branch
```

---

## Output Formats

| Flag | Format |
|------|--------|
| `--format text` | Human-readable table (default) |
| `--format json` | Structured JSON |
| `--format sarif` | SARIF 2.1.0 (GitHub Security tab) |
| `-o spdx-json` | SPDX 2.3 JSON |
| `-o cyclonedx-json` | CycloneDX JSON |

---

## Configuration

Bomly supports layered configuration with this precedence:

1. `~/.bomly/config.yaml` — user defaults
2. `<project>/.bomly/config.yaml` — project overrides
3. `--config <path>` — explicit config file
4. `BOMLY_*` environment variables
5. Command-line flags

See [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md) for the full reference and [docs/examples/bomly.config.yaml](docs/examples/bomly.config.yaml) for a working example.

---

## Plugin System

Plugins are standalone executables named `bomly-<name>`. They are discovered from `~/.bomly/plugins/` (highest priority) and `PATH`.

Each plugin declares its capabilities via `--bomly-plugin-info` and communicates with core using the `bomly-plugin-v1` JSON envelope protocol. Plugins can participate as detectors, auditors, or pre/post-resolve hooks.

See [docs/PLUGIN_GUIDE.md](docs/PLUGIN_GUIDE.md) for the full plugin development guide.

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Bomly Scan
  run: |
    bomly scan --audit --format sarif -o sarif=results.sarif
    bomly scan --audit --fail-on high
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Findings exceed `--fail-on` threshold |
| `2` | Runtime error |

---

## Architecture

Bomly is built around a modular scan pipeline:

```
Subproject Discovery → Pre-Resolve Hooks → Detect (per-ecosystem chains)
  → Consolidate → License Enrichment → Audit → Post-Resolve Hooks → Output
```

Detectors and auditors are registered per ecosystem with explicit ordering and superseding rules. Native detectors take priority over Syft-backed fallbacks; both can coexist in the same scan.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full architecture reference.

---

## Repository Structure

```
cmd/bomly/              Entry point
internal/cli/           Cobra commands, config, progress UI
internal/model/         Unified domain model (Package, Graph, Vulnerability)
internal/scan/          Scan engine, pipeline, registry
internal/detectors/     Dependency resolution per ecosystem
internal/auditors/      Vulnerability analysis (OSV, Grype)
internal/plugin/        Plugin discovery, protocol, execution
internal/sbom/          SBOM codec (SPDX 2.3, CycloneDX)
internal/output/        Output rendering (text, JSON, SARIF)
internal/enrichment/    File-backed TTL cache, VEX
internal/explain/       Dependency path traversal
internal/licenses/      License enrichment
docs/                   Architecture, specs, config reference
```

---

## Development

```bash
make build              # Build with builtin Syft/Grype
make build-lite         # Build without Syft/Grype libraries
make test               # Run all tests
make run ARGS="scan"    # Run with arguments
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development conventions and testing expectations.

---

## Supported Ecosystems

See [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) for the full matrix of native and Syft-backed ecosystem support.

---

## License

Private repository.
