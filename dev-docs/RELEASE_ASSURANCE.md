# Release assurance framework

This document is for maintainers. The user-facing explanation is
[`docs/ASSURANCE.md`](../docs/ASSURANCE.md), and the published reports live at
[bomly.dev/assurance](https://bomly.dev/assurance).

The framework has three parts:

1. a **catalog** that declares every check and every public evidence claim;
2. a **check-result contract** every check writes when it finishes;
3. a **report** built by merging results into the catalog, published per release.

Everything lives in one place. Go code is under `internal/assurance/`, data and
the public document are under `docs/assurance/`, and the workflows that run the
checks are named in each catalog entry's `source`.

## Stages

| Stage | Runs | Workflow |
| --- | --- | --- |
| `prerequisites` | Before a tag exists, on the source tree | `assurance-prerequisites.yml`, which calls `smoke.yml`, `portable-assurance.yml`, and `fuzz.yml` |
| `pre-release` | Inside the release pipeline, against the still-draft release | `release.yml` |
| `post-release` | After publication, against the shipped binaries | `assurance-assessment.yml` and `sbom-interoperability.yml` |

A stage passes when every `gate` check in it passes and no declared check is
missing. `advisory` checks are always reported and never block.

## The check-result contract

Every check writes one JSON file per instance, named `<id>[.<instance>].json`,
in the schema `bomly.assurance-check/v1`. Workflows upload those files as
`assurance-*` artifacts; later jobs download them all with `merge-multiple` and
hand the directory to the tool.

Nothing hand-writes that JSON. Four commands produce it:

```sh
# an ordinary shell step
go run ./internal/assurance/cmd emit --id cross-build --exit-code "$rc" \
  --summary "12 of 12 release targets built." \
  --metric builds_planned=12 --metric builds_completed=12 \
  --detail "linux/amd64 full=pass" --out assurance-results --step-summary
```

```sh
# a Go test slice
go test -tags smoke ./test/smoke/ -json ... | tee smoke.jsonl
go run ./internal/assurance/cmd gotest --id smoke --instance go \
  --input smoke.jsonl --exit-code "$rc" --echo --out assurance-results
```

```sh
# a tool that already writes a manifest
go run ./internal/assurance/cmd convert benchmark-run --id perf-samples \
  --input .benchmark-runs/performance/run-manifest.json --out assurance-results
```

```sh
# downloaded release assets
go run ./internal/assurance/cmd verify-release --dir assets --version 0.24.0 \
  --scope full --out assurance-results
```

`emit`, `gotest`, and `convert` read the stage and level from the catalog, so a
step only passes `--stage` when it emits something the catalog does not declare
(which the report will then flag as unknown). `--details-jsonl` reads
sub-results from a file, which keeps Windows command lines short.

Every command fills the release tag, commit, run URL, job, and runner from the
GitHub Actions environment. Set `BOMLY_ASSURANCE_TAG` when a stage runs for a
tag that is not the checked-out ref.

## Judging a stage and building the report

```sh
go run ./internal/assurance/cmd verdict --results assurance-results \
  --stage prerequisites --step-summary
```

`verdict` exits non-zero when a gate check failed or a declared check reported
nothing. That is the step that stops a release.

```sh
go run ./internal/assurance/cmd report --results assurance-results \
  --tag v0.24.0 --commit "$SHA" --url "$RELEASE_URL" --published-at "$PUBLISHED"
```

`report` writes `docs/assurance/reports/<tag>.json` and updates
`docs/assurance/index.json`, prints a markdown summary, and compares the release
against the previous one listed in the index. It exits with code 3 when a result
arrives for a check the catalog does not declare, so a renamed check cannot
silently disappear from the report (`--allow-unknown` downgrades that to a note,
which the assessment uses because the matching declared check already shows as
missing).

The assessment judges a release against **the catalog as it was at that tag**,
not the one on `main`, so a check added later is not counted as missing from an
older release. The report tooling itself comes from `main`, which is what makes
`gh workflow run assurance-assessment.yml -f tag=<old tag>` able to re-render an
old release's report after a generator fix.

The report is committed to `main` under `docs/assurance/`, because published
GitHub releases are immutable and the assessment runs after publication. The
commit uses the release app token, is marked `[skip ci]`, and retries onto
`origin/main` if the branch moved. A `bomly-assurance-report` repository
dispatch then tells the landing page a new report is available.

## Adding a check

1. Add the entry to `docs/assurance/catalog.json`: `id`, `title`, `area`,
   `stage`, `level`, `description`, `source`, optional `expected_instances`,
   `reproduce`, and — required — `proves` and `limitations` in plain language.
   Checks are sorted by `id`.
2. Emit a result from the workflow named in `source`, and upload it as an
   `assurance-<id>` artifact.
3. If the check backs a public claim, add an `evidence` entry pointing at it
   with `check_id` (and `instance`, when one specific leg proves the claim).
4. Run `make assurance-catalog`, then `go test ./internal/assurance/`.
   Refresh goldens with `go test ./internal/assurance/ -update` when the report
   shape changes.

Until the workflow actually emits the new result, every report will mark the
check `missing` — that is the intended behavior: gaps are loud.

## Evidence claims

Evidence claims are the public "we prove X, we do not prove Y" statements that
used to live in `test/evidence/cases.json`. They keep the same rigor: pinned
Git revisions, checksummed fixtures and expected-result files, explicit
reproduction commands, and mandatory limitations. `make assurance-catalog`
re-hashes every file a claim names, so a golden file cannot drift away from the
claim it supports.

Claims proven by running a workflow against a release (`release-artifact` and
`platform-matrix` levels) carry no repository checksum, because the per-release
check result is the record that they ran.

## Re-running things

```sh
gh workflow run assurance-prerequisites.yml -f ref=main
```

```sh
gh workflow run assurance-assessment.yml -f tag=v0.24.0
```

A failed prerequisites run means no tag was created, so the fix is an ordinary
pull request. A failed pre-release gate leaves a draft release and no published
version: fix the cause, delete the tag and the draft, then tag again. A failed
post-release check cannot be undone in the release, so the assessment opens a
tracking issue and the published report records the failure honestly.

`vars.RELEASE_ASSURANCE_ENFORCE` set to `false` runs everything and publishes
the report without blocking a release. Use it for the first release after a
framework change, then turn it back on.

## What the automation needs

- The Bomly Release app needs **Issues: Read and write** on `bomly-cli` for the
  per-release tracking issue. Without it the assessment still publishes the
  report and simply skips the issue.
- The prerequisites stage is found by looking for a successful job whose name
  ends in `Prerequisites verdict` among the runs for a commit. A workflow called
  with `uses:` produces no run of its own, so searching for runs of
  `assurance-prerequisites.yml` would miss every stage that Auto Version
  triggered. Keep that job name stable, or update the lookup in `release.yml`
  and `assurance-assessment.yml` with it.
- Regenerating smoke goldens changes files the evidence claims are pinned to.
  `Update Smoke Goldens` runs `catalog-validate --refresh` and commits the
  catalog alongside them; do the same when refreshing goldens by hand.

## Related documents

- [`docs/ASSURANCE.md`](../docs/ASSURANCE.md) — the public explanation
- [`dev-docs/SECURITY_ASSURANCE.md`](SECURITY_ASSURANCE.md) — trust boundaries and their regression tests
- [`dev-docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) — the release procedure
- [`test/assurance/`](../test/assurance/) — the narrative notes behind individual checks
