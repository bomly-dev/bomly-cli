# Measuring speed and stability

`make benchmark-samples` measures the same offline Bomly scan ten times:

- five runs start with an empty cache;
- five runs share a cache, like repeated scans normally do.

Running the same scan several times gives a more useful result than timing it
once. It also shows whether Bomly returns the same result every time.

The command saves its files under `.benchmark-runs`, which Git ignores. These
files include the raw command output, errors, caches, and a report named
`bomly.benchmark-run/v1`.

## What the report contains

The report includes:

- the repository revision and whether local files had changed;
- the Bomly executable's path, version, and SHA-256 checksum;
- the operating system, processor architecture, CPU count, and hostname;
- the exact command, working directory, cache setting, and network setting;
- whether each run succeeded;
- the time, peak memory, and output size for each run;
- checksums used to compare the raw and normalized output;
- summary numbers showing the typical result and how much the samples varied.

The command fails when Bomly exits with an error, when repeated runs produce
different normalized output, or when an optional output-size limit is
exceeded. It does not fail simply because one machine ran more slowly or used
more memory. Timing and memory measurements are evidence for people to review,
not fixed pass-or-fail limits.

Some JSON fields, such as timestamps and durations, naturally change on every
run. The comparison removes only those documented fields before calculating a
checksum. This comparison format is named
`bomly.benchmark-normalization/v1`. The saved raw output is never changed.

## Checking supported systems

The `Portable stability assurance` workflow runs only when someone starts it
from GitHub Actions. It:

- runs the complete test suite twice on Linux, macOS, and Windows;
- runs the Java-related tests ten times to catch intermittent failures;
- runs the complete Linux test suite five more times;
- builds both Bomly binaries for every supported Linux, macOS, and Windows
  processor target.

This workflow is separate from normal pull request checks because it performs
many repeated test runs. Use it before closing a broad assurance effort or
when investigating platform-specific or intermittent failures.
