# Release assurance

Every Bomly release goes through the same set of quality checks, in the same
order, and the results are published for that exact version. You can read them
at **[bomly.dev/assurance](https://bomly.dev/assurance)**, pick any release from
the selector, and print the page if you need a copy for a review file.

This page is for anyone who has to decide whether to adopt a Bomly release. It
explains what the checks are, when they run, and what they do and do not prove.

## Three stages

| Stage | When it runs | What it decides |
| --- | --- | --- |
| Release prerequisites | On the source tree, before a version is tagged | Whether the code is fit to be released at all |
| Final pre-release checks | After the release files are built, while the release is still a draft | Whether the files about to be published are complete, unmodified, and signed |
| Post-release assessment | After the release is published | How the binaries people actually download behave |

Splitting the work this way is deliberate. Checks that can be flaky, or that
need a fix in the source tree, run **before** a version number exists, so a
problem is fixed by a normal pull request instead of by a broken release.
Checks that describe the published files can only run once those files exist.

## How the report is organized

The report is grouped by subject (scanning real projects, SBOM compatibility,
what you download, and so on), not by release stage, and each check still says
which stage it ran in. The full list, with what every check proves and what it
does not, is the machine-readable catalog at
[`docs/assurance/catalog.json`](assurance/catalog.json). The public page is
rendered from that same file, so the two cannot disagree.

Highlights:

- **End-to-end scans.** Every supported ecosystem is scanned from a pinned
  public example project and compared against a checked-in expected result.
- **Platform stability.** The full unit test suite runs on Linux, macOS, and
  Windows, the Java detector suites run ten times because that is where
  intermittent failures have appeared, and every release binary is
  cross-compiled.
- **Parser safety.** Fuzz targets feed malformed project, configuration,
  baseline, and SBOM files to the parsers that read them.
- **Release integrity.** Checksums, the Sigstore signature, and SLSA build
  provenance are verified against the release files before publication.
- **Installation.** The published install scripts are run on all three
  operating systems against the new release.
- **SBOM interoperability.** The SBOM documents Bomly writes, including one
  merged from two source documents, are validated with the official SPDX and
  CycloneDX tools, pinned by checksum, before a version is tagged.
- **Speed and stability.** The same scan is repeated with a cold and a warm
  cache to record timing and confirm the output does not change.

Some checks stop a release when they fail; others are recorded without
blocking. A claim that was not confirmed is always shown on the page. A problem
found before publication stops the release and is fixed first. A problem found
after publication opens a tracking issue for the maintainers, so a known defect
in a released version is never dropped. Every count links to the job that
produced it, so any number on the page is one click from its log.

## Claims, checks, and evidence

The report uses three terms:

- A **claim** is one specific statement about what a release does — that it
  reads an npm lockfile correctly, or that the files you download are the ones
  we signed.
- A **check** is what asserts a claim: something that ran against that exact
  release and produced a result you can open.
- The **report as a whole** is the evidence: every claim, whether it was
  confirmed, and a link to what confirmed it.

Some claims are asserted directly by a check. Others compare a pinned input (a
public repository at a recorded commit, or a checked-in fixture) against a
recorded result file, and name the check that ran the comparison. Both appear
as claims on the page, in the section they belong to. A claim gets its own
entry only when it says something the check alone does not.

You can check the catalog yourself from a repository checkout. This command
validates the whole catalog and confirms that every expected-result file it
names exists:

```sh
make assurance-catalog
```

This one prints a single claim with the command that reproduces it:

```sh
go run ./internal/assurance/cmd catalog-validate --evidence graph-npm
```

## What a verified claim does not mean

- A passing report describes the checks listed in the catalog. Software can
  still fail in ways nobody has written a check for.
- Checks that reach live advisory services record what those services said on
  that day. That answer can change afterwards.
- Timing numbers are observations from one continuous-integration machine, not
  guarantees or limits.
- "Unreachable" in a reachability result is a confidence signal, not proof that
  a package is safe.
- Release integrity checks prove the published files are the ones this
  repository's release workflow built. They are not a review of what the code
  does.

## Related documents

- [Security and trust boundaries](SECURITY.md)
- [Network and privacy](NETWORK.md)
- [Installation](INSTALLATION.md), including how to verify checksums yourself
