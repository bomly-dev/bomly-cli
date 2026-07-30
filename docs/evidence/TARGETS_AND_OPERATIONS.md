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

The deterministic ingestion cases check Bomly's internal graph. The manually
started interoperability workflow adds an external check:

```sh
gh workflow run sbom-interoperability.yml --ref v0.20.0
```

It generates canonical SPDX 2.3 and CycloneDX 1.6 files, verifies the
downloaded validator checksums, runs the named official validators, and saves
the generated files plus a `bomly.sbom-assurance-run/v1` report. See
[`test/assurance/SBOM_INTEROPERABILITY.md`](../../test/assurance/SBOM_INTEROPERABILITY.md)
for the workflow summary and failure-investigation steps.

The public catalog records the workflow checksum under
`sbom-interoperability`. Validator versions and download checksums stay in the
workflow so changing either requires an intentional evidence update.
The `v0.20.0` release tag contains the recorded workflow definition, so this
command does not silently switch to a later default-branch workflow.

## Supported-system checks

The `portable-platforms` case starts:

```sh
gh workflow run portable-assurance.yml --ref v0.20.0
```

This workflow:

- runs the Go unit tests twice on Linux, macOS, and Windows;
- repeats Java-related unit tests ten times;
- repeats all Go unit tests five more times on Linux;
- builds full and lightweight binaries for every release target.

It is important to be precise: this is unit-test and build assurance. It does
not run smoke tests against public repositories, container registries, or
advisory services. The workflow summary identifies each group and explains
how to open failed logs. See
[`test/assurance/BENCHMARK_RUNS.md`](../../test/assurance/BENCHMARK_RUNS.md)
for the full description.

## Repeatable performance measurements

Run:

```sh
make benchmark-samples
```

The `performance-stability` case uses the checked SPDX fixture and the
lightweight Bomly binary. It records five isolated cold-cache scans and five
shared-cache warm scans under `.benchmark-runs/performance`.

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
3. Start the portable workflow and read its Summary page.
4. If SBOM output changed, start the interoperability workflow and inspect its
   generated artifact hashes and validator results.
5. Record the repository commit with every retained workflow or benchmark
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
