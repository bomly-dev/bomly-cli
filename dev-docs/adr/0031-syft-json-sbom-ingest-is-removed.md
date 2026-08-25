# ADR-0031: Syft-JSON SBOM ingest is removed; treated as any unsupported format

- **Date:** 2026-08-13
- **Status:** Accepted

Syft's proprietary JSON SBOM format is no longer an accepted `--sbom` ingest input. It had exactly one consumer in the codebase — the SBOM ingest detector — while the syft detector itself always shells out with `-o spdx-json`. The lite build (`bomly_external_syft`) never actually ingested it either: its fallback re-ran the generic decoder, which returned a nil document for the syft target, so `ToGraph(nil)` hard-failed with an unhelpful `sbom document is nil` error. The change therefore unifies full and lite behavior on one explicit, actionable rejection; the compatibility impact is on full builds only, which previously decoded the format. Removing the decode path made `internal/detectors/sbom` build-tag-free and dropped its `anchore/syft` dependency.

Follow-up simplification (same decision, second pass): the format-specific sniffing and the `syft convert` migration error were removed too. There is nothing special about syft-JSON — an unsupported format is an unsupported format, and the generic `ErrUnsupportedFormat` rejection covers it. This also deleted the last root-module import of `github.com/anchore/syft` (the `syftjson` decoder used only for identification), so the anchore tree now reaches the binary exclusively through the syft/grype component modules. Supported ingest formats are SPDX 2.3 JSON and CycloneDX 1.4–1.7 JSON.
