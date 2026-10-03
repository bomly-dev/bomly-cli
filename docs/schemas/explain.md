# Bomly Explain JSON Schema Reference

Complete reference for the `bomly explain` JSON output.

## Document

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `string` | |
| `command` | `string` | |
| `project` | [`ProjectDescriptor`](#projectdescriptor) | |
| `query` | [`ExplainQuery`](#explainquery) | |
| `dependency` | [`ExplainDependency`](#explaindependency) | |
| `paths` | Array<[`DependencyPath`](#dependencypath)> | |
| `findings` | Array<[`Finding`](#finding)> | |
| `audit_summary` | [`AuditSummary`](#auditsummary) | |
| `targets` | Array<[`ExplainTargetResponse`](#explaintargetresponse)> | |
| `warnings` | Array<[`DetectorWarning`](#detectorwarning)> | |
| `metadata` | [`Metadata`](#metadata) | |

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

### `DependencyPath`

| Field | Type | Description |
|-------|------|-------------|
| `relationship` | `string` | |
| `packages` | Array<[`PackageRef`](#packageref)> | |
| `introduced_via` | `string` | |
| `cyclic` | `boolean` | |
| `cycle_to` | `string` | |

### `DetectorWarning`

| Field | Type | Description |
|-------|------|-------------|
| `type` | `string` | |
| `code` | `string` | |
| `source` | `string` | |
| `subproject` | `string` | |
| `manifest` | `string` | |
| `message` | `string` | |

### `EPSSScore`

| Field | Type | Description |
|-------|------|-------------|
| `cve` | `string` | |
| `epss` | `number` | |
| `percentile` | `number` | |
| `date` | `string` | |

### `ExplainDependency`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `version` | `string` | |
| `scope` | `string` | |
| `purl` | `string` | |
| `id` | `string` | |
| `metadata` | `object` | |
| `locations` | Array<[`PackageLocation`](#packagelocation)> | |
| `licenses` | Array<[`PackageLicense`](#packagelicense)> | |
| `vulnerabilities` | Array<[`Vulnerability`](#vulnerability)> | |
| `scorecard` | [`PackageScorecard`](#packagescorecard) | |
| `relationship` | `string` | |
| `direct` | `boolean` | |
| `remediation` | [`PackageRemediation`](#packageremediation) | |

### `ExplainQuery`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |

### `ExplainTargetResponse`

| Field | Type | Description |
|-------|------|-------------|
| `project` | [`ProjectDescriptor`](#projectdescriptor) | |
| `detector` | `string` | |
| `package_manager` | `string` | |
| `dependency` | [`ExplainDependency`](#explaindependency) | |
| `paths` | Array<[`DependencyPath`](#dependencypath)> | |
| `findings` | Array<[`Finding`](#finding)> | |
| `audit_summary` | [`AuditSummary`](#auditsummary) | |

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

### `Metadata`

| Field | Type | Description |
|-------|------|-------------|
| `duration_ms` | `integer` | |
| `reachability_enabled` | `boolean` | |
| `scorecard_enabled` | `boolean` | |
| `analyzer_runs` | Array<`string`> | |
| `analyzer_stats` | `object` | |

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

### `PackageRef`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `version` | `string` | |
| `scope` | `string` | |
| `purl` | `string` | |
| `id` | `string` | |
| `metadata` | `object` | |
| `locations` | Array<[`PackageLocation`](#packagelocation)> | |
| `licenses` | Array<[`PackageLicense`](#packagelicense)> | |
| `vulnerabilities` | Array<[`Vulnerability`](#vulnerability)> | |
| `scorecard` | [`PackageScorecard`](#packagescorecard) | |
| `relationship` | `string` | |
| `direct` | `boolean` | |

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

### `ProjectDescriptor`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `path` | `string` | |
| `target_type` | `string` | |
| `target_ref` | `string` | |
| `ecosystem` | `string` | |
| `package_manager` | `string` | |

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

