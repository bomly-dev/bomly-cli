# Targets and operational assurance

Bomly accepts local projects, Git repositories, container images, and existing
SBOMs. The public evidence uses the same engine paths as the CLI and states
where the input itself is not immutable.

## Target cases

| Target | Public case | What is checked |
| --- | --- | --- |
| Local project | `baseline-policy` | A public Git fixture is materialized locally, then scanned and audited through `--path` |
| Git repository | `graph-npm`, `graph-go`, and the other graph cases | The CLI clones a recorded commit and runs the selected detector |
| Container image | `container-inventory` | Built-in inventory reads packages from the checked Alpine image |
| SPDX SBOM | `sbom-spdx-ingest` | The checked SPDX 2.3 graph is ingested through the SBOM detector |
| CycloneDX SBOM | `sbom-cyclonedx-ingest` | The checked CycloneDX 1.6 graph is ingested through the SBOM detector |

Inspect or reproduce one:

```sh
make evidence CASE=container-inventory
make evidence CASE=sbom-spdx-ingest
```

The container smoke case currently uses `alpine:3.20`. The tag can move, so
the checked-in golden is explicitly a snapshot rather than an immutable image
claim. The Git cases separately record the full commit behind their readable
tag or ref.

## Example SBOM workflow

A release engineer receives a supplier SBOM and wants to apply the same policy
used for source scans:

```sh
bomly scan \
  --sbom \
  --path supplier.spdx.json \
  --enrich \
  --audit \
  --fail-on high
```

The deterministic ingestion cases check Bomly's dependency graph. The
`SBOM interoperability assurance` workflow
(`.github/workflows/sbom-interoperability.yml`) in this repository adds an
external check. It runs weekly and can be started on demand:

```sh
gh workflow run sbom-interoperability.yml
```

It builds the released CLI surface, uses the binary itself to generate SPDX
2.3 and CycloneDX 1.7 files from a pinned fixture SBOM, verifies the
downloaded validator checksums, runs the official validators
(`spdx/tools-java` and `cyclonedx-cli`), and uploads the generated files,
their checksums, and the validation logs as a public run artifact.

Validator versions and download checksums stay in the workflow file, so
changing either requires an intentional, reviewable evidence update. See
[`test/assurance/SBOM_INTEROPERABILITY.md`](../../test/assurance/SBOM_INTEROPERABILITY.md)
for the workflow summary and failure-investigation steps.

## Supported-system checks

Unit-test and build assurance — the unit suite and release-target builds —
runs in this repository's public CI on every change.

The publicly verifiable evidence for this repository is:

- the `SBOM interoperability assurance` workflow described above, which
  drives the built binary and official validators in public CI;
- the smoke suite, which runs the built binary end to end against pinned
  public repositories and checked-in golden outputs;
- signed releases with SLSA build provenance, which tie each published
  binary to the public revision it was built from.

## Repeatable performance measurements

Run:

```sh
make benchmark-samples
```

The `performance-stability` case uses the checked SPDX fixture and the
lightweight Bomly binary. It records five isolated cold-cache scans and five
shared-cache warm scans under `.benchmark-runs/performance`. See
[`test/assurance/BENCHMARK_RUNS.md`](../../test/assurance/BENCHMARK_RUNS.md)
for the full description.

The resulting `bomly.benchmark-run/v1` report includes:

- repository and executable revisions and hashes;
- host and Go runtime details;
- exact command, working directory, cache mode, and network state;
- exit status, output size and hashes, timing, and peak memory for every run;
- median, variation, and an approximate 95% confidence interval.

The stable gates are successful exit status, normalized output consistency,
and an optional explicit output-size cap. Wall time and memory remain
machine-specific measurements for review rather than universal limits.

## Example release-confidence workflow

Before a broad release:

1. Run `make test` and the relevant pinned smoke slices.
2. Run `make benchmark-samples` and compare the report with the previous run
   from a comparable host.
3. If SBOM output changed, start the interoperability workflow and inspect its
   generated artifact hashes and validator results.
4. Record the repository commit with every retained workflow or benchmark
   report.

## Limits

- Remote services and package registries can be temporarily unavailable.
- Build-tool-backed graph resolution can vary with tool versions; the catalog
  states required tools and checked source revisions.
- Local repository scans can contain any number of individually bounded
  files. Per-file parser limits do not create a total project-size limit.
- Portable Git options bound time and checkout validation but cannot reliably
  cap transfer bytes or `.git` object storage before checkout completes.
- Workflow artifacts have retention periods. The workflow file, pinned tools,
  reproduction command, and result link remain public after an artifact
  expires, but the raw artifact may need to be regenerated.
