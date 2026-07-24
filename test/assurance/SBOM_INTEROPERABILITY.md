# Checking SBOM compatibility

The `SBOM interoperability assurance` workflow checks whether other tools can
read the SBOM files that Bomly creates. This catches compatibility problems
that Bomly's own tests might miss.

The workflow uses the same checked-in sample input each time. Bomly creates an
SPDX 2.3 file and a CycloneDX 1.6 file from that input. The workflow then asks
the official SPDX and CycloneDX validators to check those files.

This workflow runs only when someone starts it from GitHub Actions. It is kept
separate from normal tests because it downloads the validators and takes
longer to run. Bomly never downloads or installs these tools during normal CLI
use.

## Reading the result

Open the workflow run's **Summary** page first. It shows:

- whether validation passed;
- the version and result of each validator;
- the size and checksum of each generated file;
- any messages returned by the validators.

If validation fails, open the **Generate and validate canonical SBOMs** step
to see its full output. The summary also provides a command that downloads the
saved evidence. The downloaded `run-manifest.json` records every command, exit
code, duration, validator message, version, and checksum.

## What the workflow saves

The workflow uploads the generated SBOM files and a report named
`bomly.sbom-assurance-run/v1`. The report includes:

- the name and version of each validator;
- where each validator was downloaded from;
- a SHA-256 checksum used to confirm that each download is the expected file;
- when and where the workflow ran;
- the commands that ran and whether they succeeded;
- the output and error messages from each validator;
- the size and SHA-256 checksum of each generated SBOM.

The workflow currently uses:

- SPDX tools-java 2.0.7;
- CycloneDX CLI 0.32.0.

When updating a validator, use a separate pull request. Confirm the checksum of
the new download and run this workflow successfully. Keep generated files and
reports as GitHub Actions artifacts; do not commit them to the repository.
