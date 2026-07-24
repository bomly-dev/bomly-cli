# Bomly Diff JSON Schema Reference

Complete reference for the `bomly diff` JSON output.

## Document

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `string` | |
| `command` | `string` | |
| `project` | [`ProjectDescriptor`](#projectdescriptor) | |
| `comparison` | [`DiffComparison`](#diffcomparison) | |
| `results` | [`DiffResults`](#diffresults) | |
| `summary` | [`DiffSummary`](#diffsummary) | |
| `packages` | Array<[`ScanPackageEntry`](#scanpackageentry)> | |
| `audit` | [`DiffAudit`](#diffaudit) | |
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
| `package` | [`FindingPackageRef`](#findingpackageref) | |
| `title` | `string` | |
| `reasons` | Array<`string`> | |
| `source` | `string` | |
| `auditor` | `string` | |
| `rule_id` | `string` | |
| `policy_status` | `string` | |
| `vulnerability_id` | `string` | |
| `dependency_refs` | Array<`string`> | |

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

### `DiffAudit`

| Field | Type | Description |
|-------|------|-------------|
| `introduced` | Array<[`AuditFinding`](#auditfinding)> | |
| `resolved` | Array<[`AuditFinding`](#auditfinding)> | |
| `persisted` | Array<[`AuditFinding`](#auditfinding)> | |
| `audit_summary` | [`AuditSummary`](#auditsummary) | |

### `DiffChangedPackage`

| Field | Type | Description |
|-------|------|-------------|
| `after` | [`PackageRef`](#packageref) | |
| `before` | [`PackageRef`](#packageref) | |

### `DiffComparison`

| Field | Type | Description |
|-------|------|-------------|
| `base` | `string` | |
| `head` | `string` | |

### `DiffDependencyResults`

| Field | Type | Description |
|-------|------|-------------|
| `added` | Array<[`DiffPackageChange`](#diffpackagechange)> | |
| `removed` | Array<[`DiffPackageChange`](#diffpackagechange)> | |
| `changed` | Array<[`DiffChangedPackage`](#diffchangedpackage)> | |

### `DiffLicenseChange`

| Field | Type | Description |
|-------|------|-------------|
| `package` | [`PackageRef`](#packageref) | |
| `licenses` | Array<[`LicenseRef`](#licenseref)> | |

### `DiffLicenseDelta`

| Field | Type | Description |
|-------|------|-------------|
| `package` | [`PackageRef`](#packageref) | |
| `before` | Array<[`LicenseRef`](#licenseref)> | |
| `after` | Array<[`LicenseRef`](#licenseref)> | |

### `DiffLicenseResults`

| Field | Type | Description |
|-------|------|-------------|
| `added` | Array<[`DiffLicenseChange`](#difflicensechange)> | |
| `removed` | Array<[`DiffLicenseChange`](#difflicensechange)> | |
| `changed` | Array<[`DiffLicenseDelta`](#difflicensedelta)> | |

### `DiffManifestResult`

| Field | Type | Description |
|-------|------|-------------|
| `status` | `string` | |
| `path` | `string` | |
| `kind` | `string` | |
| `subproject` | `string` | |
| `ecosystem` | `string` | |
| `package_manager` | `string` | |
| `added` | Array<[`DiffPackageChange`](#diffpackagechange)> | |
| `removed` | Array<[`DiffPackageChange`](#diffpackagechange)> | |
| `changed` | Array<[`DiffChangedPackage`](#diffchangedpackage)> | |

### `DiffPackageChange`

| Field | Type | Description |
|-------|------|-------------|
| `package` | [`PackageRef`](#packageref) | |

### `DiffResults`

| Field | Type | Description |
|-------|------|-------------|
| `dependencies` | [`DiffDependencyResults`](#diffdependencyresults) | |
| `licenses` | [`DiffLicenseResults`](#difflicenseresults) | |
| `vulnerabilities` | [`DiffVulnerabilityResults`](#diffvulnerabilityresults) | |
| `manifests` | Array<[`DiffManifestResult`](#diffmanifestresult)> | |

### `DiffSummary`

| Field | Type | Description |
|-------|------|-------------|
| `added_manifest_count` | `integer` | |
| `changed_manifest_count` | `integer` | |
| `removed_manifest_count` | `integer` | |
| `unchanged_manifest_count` | `integer` | |
| `added_package_count` | `integer` | |
| `changed_package_count` | `integer` | |
| `removed_package_count` | `integer` | |
| `exact_match_count` | `integer` | |
| `fuzzy_match_count` | `integer` | |
| `unmatched_package_count` | `integer` | |

### `DiffVulnerabilityChange`

| Field | Type | Description |
|-------|------|-------------|
| `package` | [`PackageRef`](#packageref) | |
| `vulnerability` | [`VulnerabilityRef`](#vulnerabilityref) | |

### `DiffVulnerabilityResults`

| Field | Type | Description |
|-------|------|-------------|
| `added` | Array<[`DiffVulnerabilityChange`](#diffvulnerabilitychange)> | |
| `removed` | Array<[`DiffVulnerabilityChange`](#diffvulnerabilitychange)> | |
| `persisted` | Array<[`DiffVulnerabilityChange`](#diffvulnerabilitychange)> | |

### `Digest`

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | `string` | |
| `value` | `string` | |

### `EPSSScore`

| Field | Type | Description |
|-------|------|-------------|
| `cve` | `string` | |
| `epss` | `number` | |
| `percentile` | `number` | |
| `date` | `string` | |

### `FindingPackageRef`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `org` | `string` | |
| `version` | `string` | |
| `purl` | `string` | |
| `ecosystem` | `string` | |

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
| `relationship` | `string` | |
| `direct` | `boolean` | |

### `PackageRemediation`

| Field | Type | Description |
|-------|------|-------------|
| `status` | `string` | |
| `recommended_version` | `string` | |

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

### `ScanPackageEntry`

| Field | Type | Description |
|-------|------|-------------|
| `purl` | `string` | |
| `name` | `string` | |
| `org` | `string` | |
| `version` | `string` | |
| `ecosystem` | `string` | |
| `matched` | `boolean` | |
| `licenses` | Array<[`LicenseRef`](#licenseref)> | |
| `vulnerabilities` | Array<[`VulnerabilityRef`](#vulnerabilityref)> | |
| `scorecard` | [`PackageScorecard`](#packagescorecard) | |
| `eol` | [`PackageEOL`](#packageeol) | |
| `remediation` | [`PackageRemediation`](#packageremediation) | |
| `cpes` | Array<`string`> | |
| `digests` | Array<[`Digest`](#digest)> | |
| `metadata` | `object` | |

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

