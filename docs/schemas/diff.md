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
| `packages` | Array<[`Package`](#package)> | |
| `audit` | [`DiffAudit`](#diffaudit) | |
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

### `DiffAudit`

| Field | Type | Description |
|-------|------|-------------|
| `introduced` | Array<[`Finding`](#finding)> | |
| `resolved` | Array<[`Finding`](#finding)> | |
| `persisted` | Array<[`Finding`](#finding)> | |
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
| `transitions` | Array<[`DiffDependencyTransition`](#diffdependencytransition)> | |

### `DiffDependencyTransition`

| Field | Type | Description |
|-------|------|-------------|
| `before` | [`DiffDependencyTransitionState`](#diffdependencytransitionstate) | |
| `after` | [`DiffDependencyTransitionState`](#diffdependencytransitionstate) | |
| `changed_fields` | Array<`string`> | |

### `DiffDependencyTransitionState`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | |
| `name` | `string` | |
| `version` | `string` | |
| `purl` | `string` | |
| `scope` | `string` | |
| `relationship` | `string` | |
| `source` | `string` | |
| `registry_eligible` | `boolean` | |

### `DiffLicenseChange`

| Field | Type | Description |
|-------|------|-------------|
| `package` | [`PackageRef`](#packageref) | |
| `licenses` | Array<[`PackageLicense`](#packagelicense)> | |

### `DiffLicenseDelta`

| Field | Type | Description |
|-------|------|-------------|
| `package` | [`PackageRef`](#packageref) | |
| `before` | Array<[`PackageLicense`](#packagelicense)> | |
| `after` | Array<[`PackageLicense`](#packagelicense)> | |

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
| `transitions` | Array<[`DiffDependencyTransition`](#diffdependencytransition)> | |

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
| `transitioned_package_count` | `integer` | |
| `removed_package_count` | `integer` | |
| `exact_match_count` | `integer` | |
| `fuzzy_match_count` | `integer` | |
| `unmatched_package_count` | `integer` | |

### `DiffVulnerabilityChange`

| Field | Type | Description |
|-------|------|-------------|
| `package` | [`PackageRef`](#packageref) | |
| `vulnerability` | [`Vulnerability`](#vulnerability) | |

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

### `Metadata`

| Field | Type | Description |
|-------|------|-------------|
| `duration_ms` | `integer` | |
| `reachability_enabled` | `boolean` | |
| `scorecard_enabled` | `boolean` | |
| `analyzer_runs` | Array<`string`> | |
| `analyzer_stats` | `object` | |

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

