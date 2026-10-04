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
| `prerequisites` | Before a tag exists, on the source tree | `assurance-prerequisites.yml`, which calls `smoke.yml`, `portable-assurance.yml`, `sbom-interoperability.yml`, and `fuzz.yml` |
| `pre-release` | Inside the release pipeline, against the still-draft release | `release.yml` |
| `post-release` | After publication, against the shipped binaries | `assurance-assessment.yml` |

A stage passes when every `gate` check in it passes and no declared check is
missing. `advisory` checks are always reported and never block.

### Which stage a check belongs in

Put a check in the earliest stage that has what it needs. A check that only
needs a built binary belongs in `prerequisites`, where a failure costs a pull
request; `pre-release` is for what needs the draft's files; `post-release` is
for what cannot exist before publication — the public download, the install
scripts.

The SBOM interoperability check is the example of getting this wrong. It ran
after publication, on the reasoning that it should test the binary users
download. It needs only a build. v0.28.0 shipped a merged SPDX export the
official validator rejects, and the check reported it once the release was
public; the same job had also been failing on a weekly schedule for three
weeks, which notifies no one. It now runs in `prerequisites` and on pull
requests that touch what decides SBOM output.

## The check-result contract

Every check writes one JSON file per instance, named `<id>[.<instance>].json`,
in the schema `bomly.assurance-check/v1`. Workflows upload those files as
`assurance-*` artifacts; later jobs download them all with `merge-multiple` and
hand the directory to the tool.

Nothing hand-writes that JSON. Four commands produce it:

```sh
# an ordinary shell step
go run ./internal/assurance/cmd emit --id cross-build --instance linux --exit-code "$rc" \
  --summary "4 of 4 linux release targets built." \
  --metric builds_planned=4 --metric builds_completed=4 \
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

Every command fills the release tag, commit, job URL, job, and runner from the
GitHub Actions environment. Set `BOMLY_ASSURANCE_TAG` when a stage runs for a
tag that is not the checked-out ref.

The job URL is resolved by reading the run's job list and matching the job
running on this runner, because every instance of a matrix check shares one
run and a run-level link cannot tell a reader which platform or slice a number
came from. It costs one read of public workflow metadata, falls back to the run
URL whenever that does not work, and can be set directly with
`ASSURANCE_JOB_URL`.

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
   Checks are sorted by `id`. The `area` decides which section of the published
   page the check appears in, and the order of `areas` in the catalog is the
   order those sections are read in, so put a new area where it belongs in the
   narrative rather than at the end.
2. Emit a result from the workflow named in `source`, and upload it as an
   `assurance-*` artifact. The name only has to start with `assurance-`, since
   the stage jobs download them all with `merge-multiple`; group results by job
   when that is simpler, as the release workflow does with
   `assurance-release-<os>`.
3. If the check backs a public claim, add an `evidence` entry pointing at it
   with `check_id` (and `instance`, when one specific leg proves the claim).
   Both kinds of entry carry the same fields — title, description, proves,
   limitations — because the published page renders one shape for every claim,
   whichever way it is asserted.
4. Run `make assurance-catalog`, then `go test ./internal/assurance/`.
   Refresh goldens with `go test ./internal/assurance/ -update` when the report
   shape changes.

Until the workflow actually emits the new result, every report will mark the
check `missing` — that is the intended behavior: gaps are loud.

## Evidence claims

Evidence claims are the public "we prove X, we do not prove Y" statements that
used to live in `test/evidence/cases.json`. They keep the same rigor: pinned
Git revisions and container digests, explicit reproduction commands, and
mandatory limitations.

Fixture and expected-result files are named by path, with no checksum. A file
in this repository is already content-addressed by git — a release tag and a
path identify exact bytes, and the report records the commit — so a checksum
stored in the catalog was a second, hand-kept copy of something git knows. It
could only fall behind, and it did on every golden update: two pull requests
that each passed CI left `main` with a catalog that failed its own gate. What
is checked now is what can actually go wrong: `make assurance-catalog`, and
`TestRepositoryCatalogIsValid` in `make test`, fail when a claim names a file
that was renamed or deleted.

A claim must carry a pinned input **and** a committed artifact. That is the line
between the two layers: if a statement would only restate what its check already
reports — "the workflow ran and passed" — it belongs in the check's `proves`,
not in a second entry that says the same thing again.

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

## Ecosystem coverage

`expected_instances[].ecosystems` is what puts a language or package format on
the report's coverage list. Coverage is a single stamp per ecosystem, taking
the worst status of every check that exercised it — not a grid of which check
covered what. The reader's question is "was my ecosystem covered", and
answering it per check invites the false conclusion that a blank cell is a gap
when another check covered it. Adding an ecosystem to any check's instances is
enough to have it appear.

## Changing a schema

Four documents carry a schema version: the check result, the catalog, the
report, and the index. The report and index are read by bomly.dev, so their
versions are a contract with another repository.

- Adding an optional field keeps the version. Every consumer ignores what it
  does not know.
- Removing a field, renaming one, or changing what one means raises the version
  — and the site has to learn the new shape *first*, or reports stop appearing.
  The order is: teach `bomly-landing-page` (`SUPPORTED_REPORT_SCHEMAS` in
  `lib/assurance.ts`, `REPORT_SCHEMAS` in `scripts/sync-assurance.mjs`) to
  render both versions, ship that, then raise the version here.
- The site keeps rendering older reports it already mirrored, and skips reports
  whose version it does not know with a warning, so a mismatch shows up as one
  release missing from the page rather than a broken page.

`TestSchemaVersionsArePinned` fails on any change to these strings, so raising
one is always deliberate.

A version names a shape someone already holds. For the report and index that
starts with the first report committed to `docs/assurance/reports/`: from then
on bomly.dev has mirrored a document of that shape and the rules above apply
without exception. Before any report exists there is nothing to stay
compatible with, and the shape can still be corrected under the same version —
which is how the per-file checksums were removed from report claims before the
first release was assessed.

Nothing checks committed reports against the current shape automatically, and
that is deliberate. A test that did so was written and removed in the same
pull request: each review round found another gap in it, and comparing
published files byte for byte would have failed on a Windows checkout — in the
portable suite, which gates a release. The rule is held by
`TestSchemaVersionsArePinned`, by the report goldens (any change to the shape
shows up as a golden diff in review), and by the reviewer. If a mechanical
guard is wanted later, build it as its own change and compare the report's
JSON schema with the one recorded at the first published release, rather than
comparing committed bytes.

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
- Regenerating smoke goldens needs no catalog change; claims name their
  expected-result files by path only. Do not reintroduce a stored checksum of
  an in-repository file.

## Related documents

- [`docs/ASSURANCE.md`](../docs/ASSURANCE.md) — the public explanation
- [`dev-docs/SECURITY_ASSURANCE.md`](SECURITY_ASSURANCE.md) — trust boundaries and their regression tests
- [`dev-docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) — the release procedure
- [`test/assurance/`](../test/assurance/) — the narrative notes behind individual checks
