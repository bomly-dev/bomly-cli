# Release assurance

Every Bomly release goes through the same set of quality checks, in the same
order, and the results are published for that exact version. You can read them
at **[bomly.dev/assurance](https://bomly.dev/assurance)**, pick any release from
the selector, and print the page if you need a copy for a review file.

This page explains what the checks are, when they run, and what they do and do
not prove.

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

## What each check covers

The full list, with what every check proves and what it does not, lives in the
machine-readable catalog at
[`docs/assurance/catalog.json`](assurance/catalog.json). The assurance page
renders the same catalog, so the page and the repository can never disagree.

Highlights:

- **End-to-end scans.** Every supported ecosystem is scanned from a pinned
  public example project and compared against a checked-in expected result.
- **Platform stability.** The unit tests run repeatedly on Linux, macOS, and
  Windows, and every release binary is cross-compiled.
- **Parser safety.** Fuzz targets feed malformed project, configuration,
  baseline, and SBOM files to the parsers that read them.
- **Release integrity.** Checksums, the Sigstore signature, and SLSA build
  provenance are verified against the release files before publication.
- **Installation.** The published install scripts are run on all three
  operating systems against the new release.
- **SBOM interoperability.** The SBOM documents Bomly writes are validated with
  the official SPDX and CycloneDX tools, pinned by checksum.
- **Speed and stability.** The same scan is repeated with a cold and a warm
  cache to record timing and confirm the output does not change.

Checks are either **gates**, which stop a release, or **advisory**, which are
reported but never block. The report always says which is which.

## Evidence claims

Alongside the checks, the catalog carries **evidence claims**: specific
statements about Bomly's behavior, each with the pinned input, the exact
command to reproduce it, the expected result file, and its stated limitations.
Each claim names the check that backs it, so the report can show whether that
claim still held for the release you are looking at.

Reproduce any claim from a repository checkout:

```sh
make assurance-catalog
```

```sh
go run ./internal/assurance/cmd catalog-validate --evidence graph-npm
```

The first command validates the whole catalog, including the checksums of every
expected-result file it names. The second prints one claim with its reproduction
command.

## What a green report does not mean

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
