# JSON schemas

Bomly's `--format json` output follows a stable, versioned schema. Every command shares the same vocabulary — `manifests`, `packages`, and `findings` — described in [Architecture → Domain model](ARCHITECTURE.md#domain-model). These pages are the per-command field references, generated from the source types so they never drift from the binary.

| Command         | Schema reference                       |
|-----------------|----------------------------------------|
| `bomly scan`    | [Scan output schema](schemas/scan.md)       |
| `bomly explain` | [Explain output schema](schemas/explain.md) |
| `bomly diff`    | [Diff output schema](schemas/diff.md)       |

For when to choose JSON over the other formats, and how the same data maps onto SARIF and SBOM documents, see [Output formats](OUTPUT_FORMATS.md).
