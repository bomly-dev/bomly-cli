# ADR-0009: Detector fallbacks are loud, annotated degradations

- **Date:** 2026-07-07
- **Status:** Accepted

When a build-tool-primary detector (Maven, Gradle, Go, …) cannot produce a graph and its `sdk.FallbackDetector` succeeds instead, the scan silently loses transitive resolution — the exact capability the primary exists for. That degradation is now first-class provenance rather than a Debug-only log line:

- **Two carriers.** The pipeline stamps `FallbackFrom`/`FallbackReason` on `sdk.DetectionResult` (drives warnings and Warn logs) and nests a `ResolutionFallback` inside each entry's `ManifestMetadata.Resolution` (rides the existing resolution-provenance path into scan JSON, explain, and consolidation with no extra plumbing). The reason is stored without the `"detector <name>: "` prefix so downstream rendering does not repeat the detector name.
- **Degradation vs hand-off.** Only a real primary failure (not-ready, applicability-check error, install failure, resolve error, empty graph, scope-filter error) is annotated and warned about. `Applicable() == false` with no error is designed chain hand-off (e.g. the npm lockfile detector deferring to the native detector when no lockfile exists) and stays quiet. In chained fallbacks the outermost real failure wins, since users care about the planned primary.
- **Default visibility.** At default verbosity the CLI logger is a no-op, so the authoritative channel is the `PipelineWarning` converted from the annotation after the parallel resolve phase — it renders as a ⚠ child in the scan/explain/diff progress UI, as a yellow notice in the text report, a warning blockquote in markdown, and a `resolution.fallback` object in scan JSON. A single Warn log (`pipeline: detector fell back`) fires per unique (subproject, primary, fallback) tuple for `-v` users.
- **Stage observability.** Pipeline stages (detection, consolidation, enrichment, reachability, policy evaluation) emit Info start/completion logs with counts and durations; consolidation stays logger-free and the pipeline logs around it. Detector-internal completion lines remain owned by the detectors themselves, and recoverable detector subprocess failures log at Warn, not Error, because the pipeline degrades and continues.
- **Secret-safe subprocess logs.** Subprocess owners log the executable,
  sanitized argument list, and working directory at Debug. The shared logging
  sanitizer removes credential-shaped flag values and URL user information
  while preserving ordinary arguments for reproduction. Executable values are
  resolved binary paths or names and are assumed not to contain arguments or
  credentials. URL query values are not parsed as credentials, so callers must
  not treat URL sanitization as a general query-string redactor. The engine
  logs orchestration state but never logs raw `install_args`. At DEBUG
  verbosity (`-vv`), subprocess stderr is streamed to Bomly's stderr so users
  can diagnose package-manager, analyzer, matcher, Git, Java, and managed
  plugin failures. It is hidden at lower verbosity and is not stored in
  structured results. Because Bomly cannot reliably sanitize arbitrary tool
  output, DEBUG logs may contain credentials or other sensitive values printed
  by those tools and must be handled as sensitive data. The serialized
  `DetectionRequest.AllowStdErrLogging` field lets protocol-v1 detectors see
  that the user enabled this output; process-local `Stderr` and `Verbose`
  fields carry the destination and compatibility signal for built-ins.
