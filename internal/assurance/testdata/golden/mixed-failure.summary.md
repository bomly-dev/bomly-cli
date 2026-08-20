## ❌ Release assurance v9.9.9

0 of 3 checks passed; 1 failed and 1 reported nothing.

| Stage | Result | Checks | Passed | Failed | Missing |
| --- | --- | --- | --- | --- | --- |
| Release prerequisites | ❓ missing | 1 | 0 | 0 | 1 |
| Final pre-release checks | ❌ fail | 1 | 0 | 1 | 0 |
| Post-release assessment | ⚠️ degraded | 1 | 0 | 0 | 0 |

### Release prerequisites

| Check | Level | Result | Summary |
| --- | --- | --- | --- |
| End-to-end scans of real projects | gate | ❓ missing | 1 instance passed, 1 instance reported nothing. |

### Final pre-release checks

| Check | Level | Result | Summary |
| --- | --- | --- | --- |
| Release files match their checksums | gate | ❌ fail | 1 assets do not match SHA256SUMS: bomly_9.9.9_linux_amd64.tar.gz. |

### Post-release assessment

| Check | Level | Result | Summary |
| --- | --- | --- | --- |
| Repeated scan speed and stability | advisory | ⚠️ degraded | canonical-sbom-scan completed 5 samples per cache mode with identical normalized output (cold median 705 ms, warm median 402 ms). |

### Needs attention

- ⚠️ **Repeated scan speed and stability** (advisory, post-release) — canonical-sbom-scan completed 5 samples per cache mode with identical normalized output (cold median 705 ms, warm median 402 ms).
- ❌ **Release files match their checksums** (gate, pre-release) — 1 assets do not match SHA256SUMS: bomly_9.9.9_linux_amd64.tar.gz.
- ❓ **End-to-end scans of real projects** (gate, prerequisites) — 1 instance passed, 1 instance reported nothing. Missing: node.
- ❓ Result `mystery-check` is not declared in the assurance catalog.

### Compared with v9.9.9

- `perf-samples`: pass → degraded
- `release-checksums`: pass → fail
- `smoke`: pass → missing
- `perf-samples` cold_median_ms: 412.00 → 705.00 (+71.1%)
- `perf-samples` peak_memory_bytes: 91234304.00 → 120586240.00 (+32.2%)
- `perf-samples` warm_median_ms: 288.00 → 402.00 (+39.6%)
- `smoke` tests_passed: 42.00 → 18.00 (-57.1%)
- `smoke` tests_total: 42.00 → 18.00 (-57.1%)

