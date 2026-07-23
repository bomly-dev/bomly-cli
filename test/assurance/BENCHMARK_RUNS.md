# Benchmark run evidence

`make benchmark-samples` records a deterministic, offline canonical scan as
five isolated cold samples and five shared-cache warm samples. Raw stdout,
stderr, caches, and the machine-readable run manifest are written beneath the
ignored `.benchmark-runs` directory.

The `bomly.benchmark-run/v1` manifest records:

- repository revision and dirty state;
- executable path, version output, and SHA-256;
- UTC timestamps, runtime, operating system, architecture, CPU count, and
  hostname;
- cache and network state, command, arguments, and working directory;
- exit status, command-stage duration, peak resident memory, output byte
  counts, raw hashes, normalized hashes, and raw artifact paths per sample;
- cold and warm medians, means, standard deviations, median absolute
  deviations, approximate 95% confidence intervals, peak memory, and median
  output bytes.

Only stable invariants gate the runner: successful exit status, identical
normalized output within each cache mode, and an optional explicit output-size
cap. Wall-clock time, memory, and confidence intervals are evidence rather than
merge thresholds.

Normalization is separately versioned as
`bomly.benchmark-normalization/v1`. It removes only documented volatile JSON
timestamp and duration fields before hashing and never changes the retained
raw samples.
