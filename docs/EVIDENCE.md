# Reproducible evidence

Bomly publishes the inputs, commands, expected artifacts, and limitations
behind important behavior claims. The goal is to make a claim reviewable
without private infrastructure or a one-off demonstration.

The machine-readable catalog is
[`test/evidence/cases.json`](../test/evidence/cases.json). Check it from a
repository checkout:

```sh
make evidence
```

To inspect one case:

```sh
make evidence CASE=graph-npm
```

This verifies the recorded checksums and prints the exact command to reproduce
the case.

## Evidence levels

| Level | Meaning |
| --- | --- |
| Deterministic | Uses checked-in inputs or local services and compares a stable normalized result |
| Pinned input | Uses a public repository at a recorded commit; local tools or artifact registries can still affect build-tool-backed resolution |
| Live service | Uses a pinned project with current advisory data; the result is a dated observation |
| Manual assurance | Runs a separately started GitHub Actions workflow and saves its detailed report as an artifact |

Each catalog case must state both what it proves and what it does not prove.
Remote Git inputs include a full commit revision. Fixtures, workflows, and
expected results include SHA-256 checksums.

## Case studies

- [Dependency graph evidence](evidence/DEPENDENCY_GRAPHS.md) covers npm, pnpm,
  Yarn, Bun, Go, Python, and Maven graphs, plus visible degraded fallback
  behavior.
- [Policy and vulnerability-guidance evidence](evidence/POLICY_AND_GUIDANCE.md)
  covers vulnerability and SPDX policy, baselines, source changes, persisted
  findings, reachability tiers, and read-only remediation suggestions.
- [Targets and operational assurance](evidence/TARGETS_AND_OPERATIONS.md)
  covers local and Git projects, containers, SBOM ingestion and validation,
  repeated unit tests across supported systems, release builds, and repeatable
  performance measurements.

## Dated workflow evidence

The
[SBOM interoperability run from July 24, 2026](https://github.com/bomly-dev/bomly-cli/actions/runs/30057587653)
completed successfully at commit
`9530b9f3bfcb3fe1d2748fa2bcfadb5e53e3346c`. The workflow generated canonical
SPDX 2.3 and CycloneDX 1.6 documents and checked them with its recorded
checksum-pinned validators.

The
[portable stability run from July 24, 2026](https://github.com/bomly-dev/bomly-cli/actions/runs/30065452505)
completed successfully at commit
`e6bc5235f85dc909b6bc73f6ba9eb82c22c44ac4`. It repeated Go unit tests on
Linux, macOS, and Windows, repeated the Java-related and full Linux unit-test
suites, and built every release target. It did not run remote smoke tests.

Workflow summaries explain what ran, the result, and where to inspect failures.
Their downloadable artifacts retain detailed commands, versions, diagnostics,
and hashes where the workflow produces a run manifest.

## How to read the results

- A checked golden proves the normalized result for its recorded input. It is
  not a promise that every project in that ecosystem has the same fidelity.
- A live enrichment golden can change when advisory services add, correct, or
  withdraw records. Bomly does not claim an immutable offline advisory view.
- A package count alone is not graph proof. Review identities, versions,
  relationships, scopes, sources, and occurrence paths.
- A fallback warning means useful evidence may still exist, but coverage can
  be lower than the preferred detector.
- `unreachable` does not mean safe. The analyzer and tier define what was
  checked.
- Remediation output is read-only guidance. It does not apply or validate a
  package change.
- SBOM validation proves acceptance by the named validator versions for the
  canonical fixtures, not lossless conversion for every producer or consumer.

## Provenance

The tracked cases use Bomly-owned fixtures, Bomly-owned example repositories,
or complete public input repositories. The descriptions and test structure
are written for Bomly's own graph, pipeline, and output contracts.
