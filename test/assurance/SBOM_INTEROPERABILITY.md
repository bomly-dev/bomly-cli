# SBOM interoperability assurance

The manually dispatched `SBOM interoperability assurance` workflow generates
SPDX 2.3 and CycloneDX 1.6 JSON from the canonical committed SBOM fixture. It
then validates those generated artifacts with checksum-pinned upstream command
line tools.

This workflow is intentionally separate from ordinary tests and CLI
execution. Validator downloads occur only after an explicit workflow dispatch;
they are never runtime dependencies and are not installed by Bomly.

The uploaded `bomly.sbom-assurance-run/v1` manifest records:

- validator names, versions, release URLs, and expected SHA-256 digests;
- UTC start and finish timestamps plus runtime and host architecture;
- every executable, argument vector, exit status, duration, stdout, and
  stderr;
- generated artifact formats, byte sizes, paths, and SHA-256 digests.

The pinned validators are:

- SPDX tools-java 2.0.7;
- CycloneDX CLI 0.32.0.

Update a validator only in a dedicated review that verifies the release asset
digest and records a clean workflow run. Generated SBOMs and raw run manifests
remain workflow artifacts rather than committed golden files.
