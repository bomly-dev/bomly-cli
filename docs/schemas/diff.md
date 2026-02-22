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
| `audit` | [`DiffAudit`](#diffaudit) | |
| `metadata` | [`Metadata`](#metadata) | |

## Types

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
| `Vector` | `string` | |
| `Score` | `number` | |
| `Version` | `string` | |
| `Source` | `string` | |

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

### `LicenseRef`

| Field | Type | Description |
|-------|------|-------------|
| `value` | `string` | |
| `spdxExpression` | `string` | |
| `type` | `string` | |

### `Metadata`

| Field | Type | Description |
|-------|------|-------------|
| `duration_ms` | `integer` | |

### `PackageRef`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `version` | `string` | |
| `scope` | `string` | |
| `purl` | `string` | |
| `id` | `string` | |
| `metadata` | `object` | |
| `licenses` | Array<[`LicenseRef`](#licenseref)> | |
| `vulnerabilities` | Array<[`VulnerabilityRef`](#vulnerabilityref)> | |

### `ProjectDescriptor`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `path` | `string` | |
| `ecosystem` | `string` | |
| `package_manager` | `string` | |

### `Reference`

| Field | Type | Description |
|-------|------|-------------|
| `URL` | `string` | |
| `Type` | `string` | |

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
| `affected_version_range` | `string` | |
| `references` | Array<[`Reference`](#reference)> | |
| `kev_exploited` | `boolean` | |

