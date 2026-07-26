# Execution Boundary Assurance

Bomly can start package managers and enabled native plugins. MCP can request
the same operations as the CLI. These tests separate the controls Bomly
enforces from authority delegated to a program the user selected.

| Boundary | Regression evidence | What the evidence proves |
| --- | --- | --- |
| Managed plugin environment | `TestPluginEnvIncludesProxyAndPluginConfig`, `TestPluginEnvForwardsStandardProxyEnvWhenBomlyProxyUnset`, `TestPluginEnvDoesNotForwardUnrelatedHostEnvironment`, `TestPluginEnvOnlyWritesSelectedPluginConfig` | Managed plugins receive protocol identity, selected plugin config, and configured or standard proxy settings. Unrelated host values such as cloud tokens and database URLs are not copied. |
| Plugin lifecycle | `TestInstallDevBinaryVerifyEnableDisableAndUninstall`, `TestPrepareLoadsAndRunsExternalDetector`, `TestExternalMatcherReceivesAndReturnsRegistry` | Installation leaves a plugin disabled. Disabled plugins do not join runtime planning; an explicitly enabled plugin can run through its advertised contract. |
| Protocol and fallback behavior | `TestProtocolV1DetectorSnapshotDefaultsAbsentOptionalCapabilities`, `TestRuntimeSnapshotRejectsUnadvertisedOrMalformedRole`, `TestResolveDetectors_FallbackAnnotatesResult`, `TestPipeline_RunRecordsFallbackWarning` | Older plugins work without optional capabilities. Invalid roles fail, and detector failure uses the normal fallback path. |
| MCP default authority | `TestToolsDoNotEnableNetworkOrAnalysisByDefault` | Scan, explain, and diff requests do not enable enrichment, audit, or analysis unless their own fields request it. Hostile path, package, and Git text does not panic or silently grant those permissions. |
| MCP response size | `TestCompactScanInventoryCapIsDeterministicAndCounted`, `TestCompactScanCapsDiagnosticsWithVisibleMarker`, `TestCompactRemediationCapsAliasesAndFindingsWithCounters`, `TestCompactScanSizeStaysUnderBudget` | Compact results stay within configured collection caps and report omitted data. |
| Central remediation dependencies | `TestRemediationPackageDependencyBoundaries/central_derivation` | `go list -deps -json` checks the complete `internal/remediation` package and its transitive Bomly package graph. It cannot directly import network, OS, process, system, or cache packages, and cannot reach Git, plugins, system execution, or matcher caches transitively. The direct `os` prohibition is deliberately strict: even environment reads are rejected so this policy package cannot quietly gain ambient host authority. |
| Detector hint dependencies | `TestRemediationPackageDependencyBoundaries/detector_hint_packages` | Each package that owns built-in hints is checked at package granularity. Hint-owning detector packages cannot directly import networking, Git, matcher cache, plugin, or central remediation packages and cannot reach Bomly's Git, cache, plugin, or policy packages transitively. Detector packages legitimately retain `internal/system` and `os/exec` for their separate graph-resolution role. |
| Remediation data contract | `TestExternalDetectorProvidesAdvertisedRemediationHints`, `TestDerivePackageRemediation`, `TestDerivePackageRemediationsOverwritesAndIsIdempotent`, `TestValidateHintsSanitizesAndBoundsAdvice`, `TestCollectHintsBoundsAndSanitizesDiagnostics`, `TestDeriveRejectsUnadvertisedAndUnknownHints` | Core passes cloned data, validates occurrence references and advertised strategies, bounds provider text, and chooses status, version, and action centrally. Returned hints cannot authorize writes or execution. |
| Subprocess diagnostics | `TestSanitizeArgsRedactsCredentialValuesAndURLUserinfo`, `TestSanitizeArgsDoesNotTreatOrdinaryAuthoredFlagsAsCredentials`, `TestNewConsoleAndCommandStderr`, `TestCommandStderrNilAndHidden`, `TestInstallLogsReproducibleCommandWithoutCredentials` in PR #334 | Debug logs retain executable, credential-sanitized arguments, and working directory. Arbitrary subprocess stderr is counted but not retained or mirrored. |

## Residual Authority

MCP is not a sandbox. A requested path, Git URL, image, plugin, or
package-manager operation has the same authority it has in the CLI.

An enabled external plugin is a native process with the user's privileges. The
protocol constrains data Bomly accepts from it; it cannot prevent that process
from reading files, writing files, using the network, or starting another
program.

Detector packages combine read-only hint methods with package-manager graph
resolution. Their package dependency graphs therefore include process and
filesystem helpers by design. The SDK provider contract, cloned requests, and
core validation enforce hint behavior inside Bomly; they are architecture
controls, not an operating-system sandbox for enabled native plugins.
