# Bomly Scan JSON Schema Reference

Complete reference for the `bomly scan` JSON output.

## Document

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `string` | |
| `command` | `string` | |
| `subject` | [`Subject`](#subject) | |
| `run` | [`Run`](#run) | |
| `manifests` | Array<[`Manifest`](#manifest)> | |
| `packages` | Array<[`Package`](#package)> | |
| `findings` | Array<[`Finding`](#finding)> | |
| `audit_summary` | [`AuditSummary`](#auditsummary) | |
| `warnings` | Array<[`DetectorWarning`](#detectorwarning)> | |
| `verdict` | `string` | |
| `policy` | [`PolicyRef`](#policyref) | |
| `waivers` | Array<[`Waiver`](#waiver)> | |
| `metadata` | [`Metadata`](#metadata) | |
| `digests` | [`SectionDigests`](#sectiondigests) | |

## Types

### `Affected`

| Field | Type | Description |
|-------|------|-------------|
| `ranges` | Array<[`VersionRange`](#versionrange)> | |
| `versions` | Array<`string`> | |
| `ecosystem_specific` | `object` | |
| `database_specific` | `object` | |

### `AffectedSymbol`

| Field | Type | Description |
|-------|------|-------------|
| `symbol` | `string` | |
| `kind` | `string` | |
| `package` | `string` | |
| `module` | `string` | |
| `definition` | [`SourcePosition`](#sourceposition) | |

### `Assertions`

| Field | Type | Description |
|-------|------|-------------|
| `description` | `string` | |
| `homepage` | `string` | |
| `supplier` | [`Contact`](#contact) | |
| `originator` | [`Contact`](#contact) | |
| `external_references` | Array<[`ExternalReference`](#externalreference)> | |
| `cpes` | Array<`string`> | |
| `digests` | Array<[`Digest`](#digest)> | |
| `licenses` | Array<[`PackageLicense`](#packagelicense)> | |
| `copyright` | `string` | |

### `AuditSummary`

| Field | Type | Description |
|-------|------|-------------|
| `critical` | `integer` | |
| `high` | `integer` | |
| `medium` | `integer` | |
| `low` | `integer` | |
| `unknown` | `integer` | |
| `total` | `integer` | |

### `CVSSScore`

| Field | Type | Description |
|-------|------|-------------|
| `vector` | `string` | |
| `score` | `number` | |
| `version` | `string` | |
| `source` | `string` | |

### `CWE`

| Field | Type | Description |
|-------|------|-------------|
| `cve` | `string` | |
| `id` | `string` | |
| `source` | `string` | |
| `type` | `string` | |

### `CallFrame`

| Field | Type | Description |
|-------|------|-------------|
| `function` | `string` | |
| `package` | `string` | |
| `receiver` | `string` | |
| `position` | [`SourcePosition`](#sourceposition) | |

### `CallPath`

| Field | Type | Description |
|-------|------|-------------|
| `sink` | [`AffectedSymbol`](#affectedsymbol) | |
| `frames` | Array<[`CallFrame`](#callframe)> | |

### `Component`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `version` | `string` | |
| `role` | `string` | |
| `origin` | `string` | |

### `Contact`

| Field | Type | Description |
|-------|------|-------------|
| `kind` | `string` | |
| `name` | `string` | |
| `url` | `string` | |

### `Coordinates`

| Field | Type | Description |
|-------|------|-------------|
| `purl` | `string` | |
| `ecosystem` | `string` | |
| `package_manager` | `string` | |
| `type` | `string` | |
| `org` | `string` | |
| `name` | `string` | |
| `version` | `string` | |
| `language` | `string` | |

### `Dependency`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | |
| `name` | `string` | |
| `version` | `string` | |
| `purl` | `string` | |
| `source` | `string` | |
| `scopes` | Array<`string`> | |
| `depends_on` | Array<`string`> | |
| `matched` | `boolean` | |
| `package_ref` | `string` | |
| `locations` | Array<[`PackageLocation`](#packagelocation)> | |
| `licenses` | Array<[`PackageLicense`](#packagelicense)> | |

### `DependencyOrigin`

| Field | Type | Description |
|-------|------|-------------|
| `artifact_url` | `string` | |
| `repository` | `string` | |
| `revision` | `string` | |

### `DetectorWarning`

| Field | Type | Description |
|-------|------|-------------|
| `type` | `string` | |
| `code` | `string` | |
| `source` | `string` | |
| `subproject` | `string` | |
| `manifest` | `string` | |
| `message` | `string` | |

### `Digest`

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | `string` | |
| `value` | `string` | |
| `subject` | `string` | |

### `EPSSScore`

| Field | Type | Description |
|-------|------|-------------|
| `cve` | `string` | |
| `epss` | `number` | |
| `percentile` | `number` | |
| `date` | `string` | |

### `ExternalReference`

| Field | Type | Description |
|-------|------|-------------|
| `category` | `string` | |
| `type` | `string` | |
| `locator` | `string` | |
| `comment` | `string` | |
| `hashes` | Array<[`Digest`](#digest)> | |

### `Finding`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | |
| `kind` | `string` | |
| `title` | `string` | |
| `severity` | `string` | |
| `policy_status` | `string` | |
| `reasons` | Array<`string`> | |
| `source` | `string` | |
| `auditor` | `string` | |
| `rule_id` | `string` | |
| `vex_status` | `string` | |
| `vex_justification` | `string` | |
| `package_ref` | `string` | |
| `dependency_refs` | Array<`string`> | |
| `vulnerability_id` | `string` | |
| `decision` | [`FindingPolicyDecision`](#findingpolicydecision) | |

### `FindingPolicyDecision`

| Field | Type | Description |
|-------|------|-------------|
| `status` | `string` | |
| `source` | `string` | |
| `reason` | `string` | |

### `FixAvailable`

| Field | Type | Description |
|-------|------|-------------|
| `version` | `string` | |
| `date` | `string` | |
| `kind` | `string` | |

### `KnownExploited`

| Field | Type | Description |
|-------|------|-------------|
| `cve` | `string` | |
| `vendor_project` | `string` | |
| `product` | `string` | |
| `date_added` | `string` | |
| `required_action` | `string` | |
| `due_date` | `string` | |
| `known_ransomware_campaign_use` | `string` | |
| `notes` | `string` | |
| `urls` | Array<`string`> | |
| `cwes` | Array<`string`> | |

### `Manifest`

| Field | Type | Description |
|-------|------|-------------|
| `path` | `string` | |
| `kind` | `string` | |
| `subproject` | `string` | |
| `ecosystem` | `string` | |
| `package_manager` | `string` | |
| `detector` | `string` | |
| `resolution` | [`ResolutionMetadata`](#resolutionmetadata) | |
| `dependencies` | Array<[`Dependency`](#dependency)> | |

### `Metadata`

| Field | Type | Description |
|-------|------|-------------|
| `duration_ms` | `integer` | |
| `reachability_enabled` | `boolean` | |
| `scorecard_enabled` | `boolean` | |
| `analyzer_runs` | Array<`string`> | |
| `analyzer_stats` | `object` | |

### `Options`

| Field | Type | Description |
|-------|------|-------------|
| `enrich` | `boolean` | |
| `analyze` | `boolean` | |
| `audit` | `boolean` | |
| `fail_on` | Array<`string`> | |

### `Package`

| Field | Type | Description |
|-------|------|-------------|
| `purl` | `string` | |
| `ecosystem` | `string` | |
| `package_manager` | `string` | |
| `type` | `string` | |
| `org` | `string` | |
| `name` | `string` | |
| `version` | `string` | |
| `language` | `string` | |
| `description` | `string` | |
| `homepage` | `string` | |
| `supplier` | [`Contact`](#contact) | |
| `originator` | [`Contact`](#contact) | |
| `external_references` | Array<[`ExternalReference`](#externalreference)> | |
| `cpes` | Array<`string`> | |
| `digests` | Array<[`Digest`](#digest)> | |
| `licenses` | Array<[`PackageLicense`](#packagelicense)> | |
| `copyright` | `string` | |
| `id` | `string` | |
| `resolved_url` | `string` | |
| `detected_origins` | Array<[`DependencyOrigin`](#dependencyorigin)> | |
| `vulnerabilities` | Array<[`Vulnerability`](#vulnerability)> | |
| `attestations` | Array<[`PackageAttestation`](#packageattestation)> | |
| `scorecard` | [`PackageScorecard`](#packagescorecard) | |
| `eol` | [`PackageEOL`](#packageeol) | |
| `remediation` | [`PackageRemediation`](#packageremediation) | |
| `matched` | `boolean` | |
| `metadata` | `object` | |

### `PackageAttestation`

| Field | Type | Description |
|-------|------|-------------|
| `predicate_type` | `string` | |
| `source` | `string` | |
| `url` | `string` | |
| `digest` | [`Digest`](#digest) | |
| `issuer` | `string` | |
| `verified` | `boolean` | |

### `PackageEOL`

| Field | Type | Description |
|-------|------|-------------|
| `source` | `string` | |
| `cycle` | `string` | |
| `eol` | `boolean` | |
| `eol_date` | `string` | |
| `latest_version` | `string` | |
| `release_date` | `string` | |
| `supported` | `boolean` | |

### `PackageLicense`

| Field | Type | Description |
|-------|------|-------------|
| `value` | `string` | |
| `spdx_expression` | `string` | |
| `type` | `string` | |
| `source` | `string` | |
| `name` | `string` | |
| `extracted_text` | `string` | |

### `PackageLocation`

| Field | Type | Description |
|-------|------|-------------|
| `real_path` | `string` | |
| `access_path` | `string` | |
| `position` | [`SourcePosition`](#sourceposition) | |
| `module_root` | `string` | |
| `scopes` | Array<`string`> | |
| `relationship` | `string` | |

### `PackageRemediation`

| Field | Type | Description |
|-------|------|-------------|
| `status` | `string` | |
| `recommended_version` | `string` | |
| `suggestions` | Array<[`PackageRemediationSuggestion`](#packageremediationsuggestion)> | |

### `PackageRemediationSuggestion`

| Field | Type | Description |
|-------|------|-------------|
| `affected_dependency_refs` | Array<`string`> | |
| `suggested_action_dependency_ref` | `string` | |
| `manifest_path` | `string` | |
| `action` | `string` | |
| `override_advice` | `string` | |

### `PackageScorecard`

| Field | Type | Description |
|-------|------|-------------|
| `source` | `string` | |
| `repository` | `string` | |
| `commitSha` | `string` | |
| `scorecardVersion` | `string` | |
| `runDate` | `string` (RFC 3339 timestamp) | |
| `aggregateScore` | `number` | |
| `checks` | Array<[`PackageScorecardCheck`](#packagescorecardcheck)> | |

### `PackageScorecardCheck`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `score` | `integer` | |
| `reason` | `string` | |
| `documentation` | `string` | |

### `PolicyRef`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `digest` | `string` | |
| `evaluated_at` | `string` (RFC 3339 timestamp) | |

### `RangeEvent`

| Field | Type | Description |
|-------|------|-------------|
| `introduced` | `string` | |
| `fixed` | `string` | |
| `last_affected` | `string` | |
| `limit` | `string` | |

### `Reachability`

| Field | Type | Description |
|-------|------|-------------|
| `status` | `string` | |
| `tier` | `string` | |
| `analyzer` | `string` | |
| `reason` | `string` | |
| `symbols` | Array<[`AffectedSymbol`](#affectedsymbol)> | |
| `call_paths` | Array<[`CallPath`](#callpath)> | |
| `hops` | `integer` | |
| `confidence` | `string` | |
| `dynamic_imports_detected` | `boolean` | |
| `analyzed_at` | `string` | |
| `evidence` | Array<[`ReachabilityEvidence`](#reachabilityevidence)> | |

### `ReachabilityEvidence`

| Field | Type | Description |
|-------|------|-------------|
| `module_root` | `string` | |
| `dependency_refs` | Array<`string`> | |
| `status` | `string` | |
| `tier` | `string` | |
| `analyzer` | `string` | |
| `reason` | `string` | |
| `symbols` | Array<[`AffectedSymbol`](#affectedsymbol)> | |
| `call_paths` | Array<[`CallPath`](#callpath)> | |
| `hops` | `integer` | |
| `confidence` | `string` | |
| `dynamic_imports_detected` | `boolean` | |
| `analyzed_at` | `string` | |

### `Reference`

| Field | Type | Description |
|-------|------|-------------|
| `url` | `string` | |
| `type` | `string` | |

### `ResolutionFallback`

| Field | Type | Description |
|-------|------|-------------|
| `from` | `string` | |
| `reason` | `string` | |

### `ResolutionMetadata`

| Field | Type | Description |
|-------|------|-------------|
| `method` | `string` | |
| `install_executed` | `boolean` | |
| `install_command` | Array<`string`> | |
| `install_working_dir` | `string` | |
| `fallback` | [`ResolutionFallback`](#resolutionfallback) | |

### `Run`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | |
| `correlator` | `string` | |
| `started_at` | `string` (RFC 3339 timestamp) | |
| `completed_at` | `string` (RFC 3339 timestamp) | |
| `tool` | [`Tool`](#tool) | |
| `components` | Array<[`Component`](#component)> | |
| `options` | [`Options`](#options) | |

### `SectionDigests`

| Field | Type | Description |
|-------|------|-------------|
| `manifests` | `string` | |
| `packages` | `string` | |
| `findings` | `string` | |

### `Severity`

| Field | Type | Description |
|-------|------|-------------|
| `type` | `string` | |
| `score` | `string` | |

### `SourcePosition`

| Field | Type | Description |
|-------|------|-------------|
| `file` | `string` | |
| `line` | `integer` | |
| `column` | `integer` | |
| `end_line` | `integer` | |

### `Subject`

| Field | Type | Description |
|-------|------|-------------|
| `kind` | `string` | |
| `repository_url` | `string` | |
| `ref` | `string` | |
| `commit_sha` | `string` | |
| `image_reference` | `string` | |
| `image_digest` | `string` | |

### `Tool`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `version` | `string` | |

### `VersionRange`

| Field | Type | Description |
|-------|------|-------------|
| `type` | `string` | |
| `repo` | `string` | |
| `events` | Array<[`RangeEvent`](#rangeevent)> | |

### `Vulnerability`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | |
| `aliases` | Array<`string`> | |
| `related` | Array<`string`> | |
| `summary` | `string` | |
| `details` | `string` | |
| `severity` | Array<[`Severity`](#severity)> | |
| `affected` | Array<[`Affected`](#affected)> | |
| `references` | Array<[`Reference`](#reference)> | |
| `published` | `string` | |
| `modified` | `string` | |
| `withdrawn` | `string` | |
| `database_specific` | `object` | |
| `source` | `string` | |
| `data_source` | `string` | |
| `namespace` | `string` | |
| `title` | `string` | |
| `reasons` | Array<`string`> | |
| `parsed_severity` | `string` | |
| `severity_source` | `string` | |
| `cvss` | Array<[`CVSSScore`](#cvssscore)> | |
| `epss` | Array<[`EPSSScore`](#epssscore)> | |
| `cwes` | Array<[`CWE`](#cwe)> | |
| `kev_exploited` | `boolean` | |
| `known_exploited` | Array<[`KnownExploited`](#knownexploited)> | |
| `risk_score` | `number` | |
| `fix_state` | `string` | |
| `fixed_in` | `string` | |
| `fixed_versions` | Array<`string`> | |
| `fix_available` | Array<[`FixAvailable`](#fixavailable)> | |
| `affected_version_range` | `string` | |
| `cpes` | Array<`string`> | |
| `affected_symbols` | Array<[`AffectedSymbol`](#affectedsymbol)> | |
| `reachability` | [`Reachability`](#reachability) | |
| `analysis` | [`VulnerabilityAnalysis`](#vulnerabilityanalysis) | |
| `recommendation` | `string` | |

### `VulnerabilityAnalysis`

| Field | Type | Description |
|-------|------|-------------|
| `state` | `string` | |
| `justification` | `string` | |
| `response` | Array<`string`> | |
| `detail` | `string` | |
| `first_issued` | `string` | |
| `last_updated` | `string` | |

### `Waiver`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | |
| `package_ref` | `string` | |
| `vulnerability_id` | `string` | |
| `rule_id` | `string` | |
| `justification` | `string` | |
| `approved_by` | `string` | |
| `created_at` | `string` (RFC 3339 timestamp) | |
| `expires_at` | `string` (RFC 3339 timestamp) | |

