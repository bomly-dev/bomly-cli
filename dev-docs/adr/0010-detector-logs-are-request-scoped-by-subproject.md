# ADR-0010: Detector logs are request-scoped by subproject

- **Date:** 2026-07-07
- **Status:** Accepted

The detect stage resolves subprojects concurrently (`resolveAll` fans out to per-subproject worker goroutines), and a single detector *instance* registered in the registry serves all of them. At `-v`/`-vv` that meant detector log lines from several subprojects interleaved with no way to tell which subproject a line belonged to. Rather than tag lines with an opaque goroutine or worker id (Go hides goroutine ids by design, and a worker processes many subprojects over its life), the pipeline injects a **request-scoped logger** keyed by the thing that actually correlates the lines — the subproject and detector:

- `sdk.DetectionRequest` carries a process-local `Logger *zap.Logger` (`json:"-"`, alongside the existing `Stderr`/`Verbose` runtime fields) and a `DetectorLogger(fallback)` helper that prefers the request logger, then the detector's instance logger, then a no-op — never nil.
- `resolveDetector` sets `req.Logger = p.detectorLogger(subproject, detector)`, which names the logger after the subproject (rendered as a console prefix, e.g. `scan.services/api`) and attaches `detector` as a field. It is re-derived from `p.Logger` on every call so a fallback detector is labelled with its own name, not the primary's.
- Each detector's public `ResolveGraph` rebinds `d.Logger = req.DetectorLogger(d.Logger)` on its value-receiver copy, so every private helper inherits the scoped logger with no signature churn and no shared mutable state.
- The console encoder enables `NameKey`/`EncodeName` so the subproject scope renders as a prefix. Logs remain real-time (not buffered per subproject) because `-vv` is used precisely to watch slow or hung detectors.
