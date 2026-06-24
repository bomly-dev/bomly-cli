# Bomly Explain JSON Schema Reference

Complete reference for the `bomly explain` JSON output.

## Document

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `string` | |
| `command` | `string` | |
| `project` | [`ProjectDescriptor`](#projectdescriptor) | |
| `query` | [`ExplainQuery`](#explainquery) | |
| `dependency` | [`PackageRef`](#packageref) | |
| `paths` | Array<[`DependencyPath`](#dependencypath)> | |
| `findings` | Array<[`AuditFinding`](#auditfinding)> | |
| `audit_summary` | [`AuditSummary`](#auditsummary) | |
| `targets` | Array<[`ExplainTargetResponse`](#explaintargetresponse)> | |
| `metadata` | [`Metadata`](#metadata) | |

## Types

### `AffectedSymbol`

| Field | Type | Description |
|-------|------|-------------|
| `symbol` | `string` | |
| `kind` | `string` | |
| `package` | `string` | |
| `module` | `string` | |
| `definition` | [`SourcePosition`](#sourceposition) | |

### `AuditFinding`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | |
| `kind` | `string` | |
| `severity` | `string` | |
| `package` | [`PackageRef`](#packageref) | |
| `title` | `string` | |
| `reasons` | Array<`string`> | |
| `source` | `string` | |
| `auditor` | `string` | |
| `disposition` | `string` | |
| `fixed_in` | `string` | |
| `fixed_versions` | Array<`string`> | |
| `fix_state` | `string` | |
| `fix_available` | Array<[`FixAvailable`](#fixavailable)> | |
| `aliases` | Array<`string`> | |
| `description` | `string` | |
| `severity_source` | `string` | |
| `cvss` | Array<[`CVSSScore`](#cvssscore)> | |
| `affected_version_range` | `string` | |
| `references` | Array<[`Reference`](#reference)> | |
| `kev_exploited` | `boolean` | |
| `known_exploited` | Array<[`KnownExploited`](#knownexploited)> | |
| `epss` | Array<[`EPSSScore`](#epssscore)> | |
| `cwes` | Array<[`CWE`](#cwe)> | |
| `risk_score` | `number` | |
| `data_source` | `string` | |
| `namespace` | `string` | |
| `cpes` | Array<`string`> | |
| `reachability` | [`Reachability`](#reachability) | |

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

### `EPSSScore`

| Field | Type | Description |
|-------|------|-------------|
| `cve` | `string` | |
| `epss` | `number` | |
| `percentile` | `number` | |
| `date` | `string` | |

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
| `dependency` | [`PackageRef`](#packageref) | |
| `paths` | Array<[`DependencyPath`](#dependencypath)> | |
| `findings` | Array<[`AuditFinding`](#auditfinding)> | |
| `audit_summary` | [`AuditSummary`](#auditsummary) | |

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

### `LicenseRef`

| Field | Type | Description |
|-------|------|-------------|
| `value` | `string` | |
| `spdxExpression` | `string` | |
| `type` | `string` | |

### `LocationRef`

| Field | Type | Description |
|-------|------|-------------|
| `real_path` | `string` | |
| `access_path` | `string` | |
| `position` | [`PositionRef`](#positionref) | |

### `Metadata`

| Field | Type | Description |
|-------|------|-------------|
| `duration_ms` | `integer` | |
| `reachability_enabled` | `boolean` | |
| `scorecard_enabled` | `boolean` | |
| `analyzer_runs` | Array<`string`> | |
| `analyzer_stats` | `object` | |

### `PackageRef`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `version` | `string` | |
| `scope` | `string` | |
| `purl` | `string` | |
| `id` | `string` | |
| `metadata` | `object` | |
| `locations` | Array<[`LocationRef`](#locationref)> | |
| `licenses` | Array<[`LicenseRef`](#licenseref)> | |
| `vulnerabilities` | Array<[`VulnerabilityRef`](#vulnerabilityref)> | |
| `scorecard` | [`PackageScorecard`](#packagescorecard) | |
| `direct` | `boolean` | |

### `PackageScorecard`

| Field | Type | Description |
|-------|------|-------------|
| `source` | `string` | |
| `repository` | `string` | |
| `commitSha` | `string` | |
| `scorecardVersion` | `string` | |
| `runDate` | [`Time`](#time) | |
| `aggregateScore` | `number` | |
| `checks` | Array<[`PackageScorecardCheck`](#packagescorecardcheck)> | |

### `PackageScorecardCheck`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `score` | `integer` | |
| `reason` | `string` | |
| `documentation` | `string` | |

### `PositionRef`

| Field | Type | Description |
|-------|------|-------------|
| `file` | `string` | |
| `line` | `integer` | |
| `column` | `integer` | |
| `end_line` | `integer` | |

### `ProjectDescriptor`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `path` | `string` | |
| `target_type` | `string` | |
| `target_ref` | `string` | |
| `ecosystem` | `string` | |
| `package_manager` | `string` | |

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

### `Reference`

| Field | Type | Description |
|-------|------|-------------|
| `url` | `string` | |
| `type` | `string` | |

### `SourcePosition`

| Field | Type | Description |
|-------|------|-------------|
| `file` | `string` | |
| `line` | `integer` | |
| `column` | `integer` | |
| `end_line` | `integer` | |

### `Time`

### `VulnerabilityRef`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | |
| `source` | `string` | |
| `title` | `string` | |
| `severity` | `string` | |
| `severity_source` | `string` | |
| `aliases` | Array<`string`> | |
| `description` | `string` | |
| `reasons` | Array<`string`> | |
| `cvss` | Array<[`CVSSScore`](#cvssscore)> | |
| `fixed_in` | `string` | |
| `fixed_versions` | Array<`string`> | |
| `fix_state` | `string` | |
| `fix_available` | Array<[`FixAvailable`](#fixavailable)> | |
| `affected_version_range` | `string` | |
| `references` | Array<[`Reference`](#reference)> | |
| `kev_exploited` | `boolean` | |
| `known_exploited` | Array<[`KnownExploited`](#knownexploited)> | |
| `epss` | Array<[`EPSSScore`](#epssscore)> | |
| `cwes` | Array<[`CWE`](#cwe)> | |
| `risk_score` | `number` | |
| `data_source` | `string` | |
| `namespace` | `string` | |
| `cpes` | Array<`string`> | |
| `affected_symbols` | Array<[`AffectedSymbol`](#affectedsymbol)> | |
| `reachability` | [`Reachability`](#reachability) | |

