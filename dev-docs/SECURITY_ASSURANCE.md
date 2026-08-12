# Security Assurance Inventory

This document records Bomly's current trust boundaries, the control used at
each boundary, and the regression evidence that supports it. It separates
Bomly guarantees from authority delegated to user-selected tools and native
plugins.

The shorter user guide is [`docs/SECURITY.md`](../docs/SECURITY.md).

## Authority Model

Bomly grants authority from explicit user choices:

| Choice | Authority granted |
| --- | --- |
| `--config` or `BOMLY_CONFIG` | Load the complete selected configuration, including target, network, plugin, subprocess, and output settings |
| `--url` | Let Git contact the selected remote and materialize it in a temporary directory |
| `--enrich` | Run the selected matchers and their documented network or database work |
| A build-tool detector | Run the selected host package manager to resolve the graph |
| `--install-first` | Run the detector's package installation command before resolution |
| `bomly plugins enable` | Run that native plugin with the Bomly process user's privileges |
| An output path | Create or replace that specific output |

The user configuration at `~/.bomly/config.yaml` is trusted and loads
automatically. Repository configuration is never automatic. Automatic baseline
discovery is retained because a baseline has one narrow power: it can change a
finding's policy status. It cannot select a target, enable network access,
start a subprocess, enable a plugin, or choose an output path.

## Boundary Inventory

| Boundary | Controls and guarantees | Regression evidence | Residual risk or delegated authority |
| --- | --- | --- | --- |
| Repository configuration | Only the user config loads automatically. Repository config requires `--config` or `BOMLY_CONFIG`; the flag wins. Explicit selections must be regular files. | `TestCommandContextInitialize_RequiresExplicitProjectConfig`, `TestCommandContextInitialize_RepositoryConfigCannotGrantAuthorityImplicitly`, `TestCommandContextInitialize_ConfigSelection` | A selected config is trusted and may grant every configured authority. |
| Matcher network intent | The engine returns before matcher readiness or execution unless enrichment or the internal explicit matching signal is enabled. Audit and analysis alone do not enable matching. | `TestPipelineRequiresExplicitMatcherIntent` | URL cloning and detector subprocess traffic are separate boundaries. |
| Shared HTTP client | Bomly and standard no-proxy lists are combined. Custom CAs, standard redirects, same-host credential preservation, cross-host credential removal, and secret-safe errors are tested. Endpoint credentials are redacted from registration logs. | `TestNewHTTPClientMergesNoProxyWithStandardProxyFallback`, `TestNewHTTPClientMergesNoProxyWithExplicitProxy`, `TestHTTPClientRoutesRequestsThroughExplicitProxy`, `TestHTTPClientBypassesExplicitProxyForNoProxyDestination`, `TestHTTPClientNoProxyMatchesHostsAndNetworks`, `TestHTTPClientTrustsConfiguredAdditionalCA`, `TestHTTPClientPreservesCredentialsOnSameHostRedirect`, `TestHTTPClientFollowsRedirectToPrivateDestinationWithoutForwardingCredentials`, `TestHTTPClientTransportErrorDoesNotExposeEndpointPassword`, `TestRegisterScorecardMatcherDoesNotLogEndpointCredentials` | Trusted configuration may select private or plain-HTTP endpoints. Standard redirects may downgrade HTTPS to HTTP. Bomly does not block private addresses, pin DNS answers, prevent DNS rebinding, or block that downgrade. Native plugins can use their own clients. |
| Git targets and refs | Remote Git work has a 10-minute deadline and cleans its temporary directory after failure or completion. Every remote clone and ref checkout disables submodule recursion and Git LFS smudging. After checkout it permits at most 1,000,000 paths, 10 GiB of regular files, and 256 path levels. A remote repository symlink must resolve within the checkout. Local ref materialization does not modify the source checkout and preserves its trusted symlinks. Recognized credential-shaped argument values and URL user information are removed from Git command logs. | `TestCloneTempMaterializesRequestedCommitWithoutChangingSource`, `TestMaterializeLocalRefKeepsRepositorySymlinksAsSymlinks`, `TestMaterializeRemoteRefRejectsEscapingRepositorySymlink`, `TestMaterializationGitArgumentsDisableSubmoduleRecursion`, `TestMaterializationGitEnvironmentDisablesLFSSmudge`, `TestValidateMaterializedTreeResourceBoundaries`, `TestRunGitContextHonorsCancellation`, `TestCloneIntoRedactsUserinfoAndPreservesExitError`, `TestSanitizeArgsRedactsCredentialValuesAndURLUserinfo` | `--url` explicitly grants Git network and disk use. Git can consume transfer bytes and `.git` object storage before Bomly inspects the completed checkout, so those resources need an operating-system quota when a hard pre-checkout cap is required. Git and its credential helpers remain trusted host tools. The hidden maintainer benchmark uses a separate shallow clone runner and is outside this customer CLI boundary. |
| Container images and registries | An image reference is an explicit target. Syft receives that reference through the detector contract; the lite build runs the external Syft command through the secret-safe subprocess boundary. | `TestCommandContextResolveExecutionTarget_Image`, `TestDetectorApplicable_ContainerTarget`, `TestSyftSourceInput_UsesContainerReferenceForContainerTargets`, container diff tests | Syft and the host registry configuration own authentication, pulls, cache behavior, and network traffic. Bomly does not provide a registry sandbox or offline guarantee. |
| Repository manifests, lockfiles, and analyzer source | In-process file reads have a 64 MiB per-file limit that is checked before and during the read. Parsers never receive a partial over-limit document. Discovery is scoped to the selected target, does not follow directory symlinks, and has depth and exclusion controls. Pure parsers have registered fuzz targets and malformed-input tests. | `TestSDKContractReadLimitEnforcesBoundsAndGrowth`, `TestSDKContractReadRepositoryFileEnforces64MiBBound` (local contracts; full suite upstream in `bomly-dev/bomly-sdk` `system/read_test.go`), `test/assurance/REPOSITORY_INPUT_LIMITS.md`, `test/assurance/PARSER_FUZZING.md`, `scripts/run-fuzz.sh`, detector and analyzer package tests | A selected package manager's command output is not truncated because partial output could produce an incomplete graph. A local target may contain an unbounded number of individually bounded files. |
| Project discovery and baselines | Recursive discovery does not follow directory symlinks. Automatic baseline selection warns and ignores a symlinked `.bomly` directory or baseline file. Explicit baseline selection may use a symlink because the user chose that path. Baseline JSON is limited to 16 MiB and 10,000 entries, is strict, and validates duplicates in linear time. It can only supply policy-status decisions. | `TestPlanSubprojectsRecursiveDoesNotFollowSymlinkedDirs`, `TestResolversForTargetIgnoresAutomaticSymlinksAndAllowsExplicitSelection`, `TestResolversForTargetAllowsUserSelectedSymlinkAsProjectRoot`, `TestLoadRejectsMalformedAndUnsupportedDocuments`, `TestLoadRejectsOversizedBaseline`, `TestDocumentEntryLimit`, `TestDocumentRejectsIndexedAdvisoryOverlap`, `FuzzLoad` | An explicitly selected baseline path is trusted and may be a symlink. |
| SBOM and configuration input | Configuration reads are limited to 4 MiB and SBOM reads to 256 MiB before parsing. Strict configuration parsing rejects unknown keys. SBOM parsers are fuzzed and oversized documents fail clearly. | `TestSDKContractReadLimitEnforcesBoundsAndGrowth`, `TestLoadFileRejectsOversizedFile`, `TestDetectorResolveGraph_RejectsOversizedSBOM`, `FuzzLoadFile`, `FuzzUnmarshalAutoJSON` | A user-selected file can still consume work up to its limit. |
| Plugin download and extraction | Direct URL packages require a checksum unless the user explicitly bypasses it. GitHub release metadata is limited to 4 MiB. ZIP and tar extraction reject traversal, links, and special files. Downloads are limited to 256 MiB; archives to 4,096 entries, 256 MiB per expanded file, and 512 MiB total. Partial files are removed. | `TestResolveGitHubReleaseRejectsOversizedMetadata`, `TestExtractZipArchiveRejectsEscapingAndSymlinkEntries`, `TestExtractTarGzArchiveRejectsEscapingLinksAndSpecialFiles`, `TestCopyDownloadWithLimit`, `TestInstallRemoteArchiveRejectsDeclaredDownloadOverLimit`, `TestArchiveExtractionLimitsAtBoundary`, `TestArchiveExtractionRejectsResourceLimits`, `TestWriteArchiveFileRemovesPartialFileAtLimit` | `--insecure-skip-checksum` is an explicit integrity bypass. |
| Plugin metadata and lifecycle | Manifests and runtime snapshots are limited to 1 MiB; the installed database is limited to 16 MiB. Plugins are installed disabled. Only enabled plugins register or run. The managed environment is allowlisted. | `TestReadFileWithLimitAcceptsExactBoundary`, `TestReadFileWithLimitRejectsOverBoundary`, `TestPluginJSONReadersRejectOversizedFiles`, `TestInstallDevBinaryVerifyEnableDisableAndUninstall`, `TestPrepareLoadsAndRunsExternalDetector`, `TestProtocolV1DetectorSnapshotDefaultsAbsentOptionalCapabilities`, `TestPluginEnvDoesNotForwardUnrelatedHostEnvironment` | Enabled plugins are trusted native processes with the user's privileges. The protocol is not an OS sandbox. |
| Package-manager and detector subprocesses | Debug logs contain executable, sanitized arguments, working directory, and raw subprocess stderr. Credential-like flag values and URL user information are redacted from command arguments. Raw stderr is hidden below debug verbosity and is not added to structured results. Build-tool commands have existing timeouts where their detector contract supplies one. | `TestSDKContractSanitizeArgsRedactsCredentials`, `TestSDKContractCommandStderrHiddenBelowDebug` (local contracts; full suites upstream in `bomly-dev/bomly-sdk` `logkit/command_test.go` and `logkit/stderr_test.go`), `TestNewConsole` (`internal/logging/logger_test.go`), `TestInstallLogsReproducibleCommandAndDebugStderr`, `TestRunGitLogsStderrAtDebug`, Java readiness command tests, representative detector command-log tests | The selected executable, its credential store, registry configuration, network traffic, and filesystem behavior are trusted host concerns. Bomly cannot reliably sanitize arbitrary tool output. Debug stderr may contain credentials or other sensitive values and users must handle debug logs as sensitive data. |
| Matcher responses and caches | Built-in matcher responses have byte limits. Oversized responses fail before JSON decoding, and non-success errors do not copy arbitrary response bodies into diagnostics. Cache identities are hashed before becoming paths. One cache entry may contain at most 64 MiB; corrupt and oversized entries degrade to a miss. | `TestSDKContractReadLimitEnforcesBoundsAndGrowth`, `TestClientRejectsOversizedVulnerabilityResponse`, `TestClientRejectsOversizedBatchResponse`, `TestFetchKEVCatalogRejectsOversizedResponse`, `TestClientRejectsOversizedResponse`, `TestFetchBatchRejectsOversizedResponse`, `TestOSVAndKEVErrorsDoNotExposeResponseBodies`, `TestClientErrorDoesNotExposeResponseBody`, `TestFetchBatchDoesNotExposeErrorResponseBody`, `TestSDKContractFileCachePermissionsAndContainment` (local contract; full suite upstream in `bomly-dev/bomly-sdk` `filecache/cache_test.go`) | Cache directories remain local user-controlled state. Matcher freshness depends on each matcher's documented cache policy. |
| Output paths and atomic state | `baseline.WriteAtomic` validates before a same-directory temporary-file rename and rejects a final symlink. The installed-plugin database also uses a same-directory temporary file and rename. General structured and SBOM output writes only to the explicitly selected destination; it is not the baseline writer's atomic or symlink-rejecting contract. | `TestWriteAtomicLoadAndRejectSymlink`, `TestWriteAtomicValidationFailurePreservesExistingDocument`, `TestWriteOutputDocumentWritesOnlyToExplicitDestination` | Selecting a general output grants permission to create or replace that path, including following a user-selected final symlink. Parent-directory permissions remain an OS concern. |
| MCP | Request fields do not enable enrichment or analysis implicitly. Response collections have caps and truncation counters. Fatal tool failures expose stable categories rather than adapter or encoding details. Local MCP error logs contain the category and unwrapped Go cause type, never the raw cause text; components may emit safe stage logs independently. | `TestToolsDoNotEnableNetworkOrAnalysisByDefault`, `TestToolErrorsDoNotExposeAdapterDetails`, `TestToolErrorsExposeOnlyStableCategories`, `TestWrapToolErrorPreservesInternalCause`, `TestToolErrorLogsDoNotExposeAdapterDetails`, `TestJSONResultDoesNotExposeEncodingDetails`, `TestCompactScanInventoryCapIsDeterministicAndCounted`, `TestCompactScanCapsDiagnosticsWithVisibleMarker`, `TestCompactRemediationCapsAliasesAndFindingsWithCounters`, `TestCompactScanSizeStaysUnderBudget` | Generic validation categories may require the caller to inspect the tool schema or retry with fewer options. The MCP host controls process launch, filesystem reach, and any OS sandbox. Enabled plugins keep their normal authority. |
| Vulnerability remediation | Remediation runs after vulnerability consolidation as a read-only enrichment join. Core clones detector inputs, validates advertised strategies and occurrence references, bounds advice and diagnostics, and chooses the final action and version centrally. | `TestRemediationPackageDependencyBoundaries`, `TestExternalDetectorProvidesAdvertisedRemediationHints`, `TestDerivePackageRemediation`, `TestDerivePackageRemediationsOverwritesAndIsIdempotent`, `TestValidateHintsSanitizesAndBoundsAdvice`, `TestCollectHintsBoundsAndSanitizesDiagnostics`, `TestDeriveRejectsUnadvertisedAndUnknownHints` | A native detector plugin remains capable of independent host activity because it is already trusted and enabled. Its returned hint cannot grant core new authority. |

## CI Credential and Permission Inventory

Every workflow declares top-level permissions. Jobs that need write access add
only their required permissions.

| Workflow | Default permission | Elevated jobs and reason |
| --- | --- | --- |
| `ci.yml` | `contents: read` | None |
| `fuzz.yml` | `contents: read` | None |
| `version.yml` | `contents: write` | Pushes an annotated release tag with the default `GITHUB_TOKEN`; manual dispatch from `main` only |

Third-party actions are pinned. This repository holds no long-lived publishing
credentials: smoke testing, release packaging, signing, provenance, and
npm/MCP-registry publication run in the public `bomly-cli` distribution
repository, whose own security assurance doc inventories those workflows and
their credentials.

## Evidence Changes

The assurance work is split so each control can be reviewed independently:

| Change | Evidence supplied |
| --- | --- |
| [PR #320](https://github.com/bomly-dev/bomly-cli/pull/320) | Explicit repository configuration trust |
| [PR #324](https://github.com/bomly-dev/bomly-cli/pull/324) | Matcher network intent and corrected trust language |
| [PR #325](https://github.com/bomly-dev/bomly-cli/pull/325) | Standard proxy fallback honors Bomly no-proxy settings |
| [PR #326](https://github.com/bomly-dev/bomly-cli/pull/326) | Filesystem, archive, cache, Git, and output containment; `test/assurance/SECURITY_CONTAINMENT.md` |
| [PR #327](https://github.com/bomly-dev/bomly-cli/pull/327) | Endpoint credential redaction |
| [PR #328](https://github.com/bomly-dev/bomly-cli/pull/328) | Plugin, MCP, subprocess-environment, and remediation execution boundaries; `test/assurance/EXECUTION_BOUNDARIES.md` |
| [PR #329](https://github.com/bomly-dev/bomly-cli/pull/329) | Proxy, CA, redirect, private-endpoint, and HTTP error behavior; `test/assurance/NETWORK_BOUNDARIES.md` |
| [PR #330](https://github.com/bomly-dev/bomly-cli/pull/330) | Automatic baseline path containment |
| [PR #331](https://github.com/bomly-dev/bomly-cli/pull/331) | Stable, secret-safe MCP tool errors |
| [PR #332](https://github.com/bomly-dev/bomly-cli/pull/332) | Plugin download, extraction, and metadata resource limits |
| [PR #334](https://github.com/bomly-dev/bomly-cli/pull/334) | Reproducible command logs with sanitized arguments and no raw subprocess diagnostics |
| [PR #336](https://github.com/bomly-dev/bomly-cli/pull/336) | Configuration, baseline, SBOM, and deps.dev response limits |

This assurance document must merge after every listed production and test
change. Until then, its tables describe the intended combined state rather
than the behavior of an earlier individual branch.

## Acceptance Disposition

| Requirement | Disposition after the evidence changes merge |
| --- | --- |
| Every current trust boundary has a control and regression evidence | Accepted. Deliberate delegated authority and unbounded local resources are recorded above. |
| Debug logging supports subprocess diagnosis with a clear trust boundary | Accepted. Commands retain executable, sanitized arguments, and working directory. Raw stderr is available only at debug verbosity, is excluded from structured results, and is explicitly documented as potentially sensitive. |
| Claims separate guarantees from best-effort safeguards | Accepted. Private endpoints, native plugins, Git and repository resource use, host tools, and local caches are explicit residuals. |
| MCP cannot implicitly enable enrichment or analysis or expose adapter details | Accepted by request-authority, compact-limit, and stable-error tests. |
| Automatic baselines remain policy-only and fail safely | Accepted by authority, path, parser, resource, and policy-resolution tests. |
| Remediation remains read-only and grants no new authority | Accepted by source-boundary, provider, validation, and derivation tests. |

## Review Checklist

When a new input, network client, subprocess, plugin role, output path, MCP
field, or automatic repository file is introduced:

1. State which user action grants its authority.
2. Bound untrusted bytes, collection sizes, nesting, or execution time where a
   practical bound exists.
3. Keep credentials and arbitrary remote or subprocess text out of logs and
   client-facing errors.
4. Add positive and hostile regression tests.
5. Update this inventory and the public security guide.
