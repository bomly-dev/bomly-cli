# Bomly Scan JSON Schema Reference

Complete reference for the `bomly scan` JSON output.

## Document

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `string` | |
| `command` | `string` | |
| `project` | [`ProjectDescriptor`](#projectdescriptor) | |
| `manifests` | Array<[`ScanManifest`](#scanmanifest)> | |
| `findings` | Array<[`AuditFinding`](#auditfinding)> | |
| `audit_summary` | [`AuditSummary`](#auditsummary) | |
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
| `licenses` | Array<[`LicenseRef`](#licenseref)> | |

### `ProjectDescriptor`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `path` | `string` | |
| `ecosystem` | `string` | |
| `package_manager` | `string` | |

### `ScanManifest`

| Field | Type | Description |
|-------|------|-------------|
| `path` | `string` | |
| `kind` | `string` | |
| `subproject` | `string` | |
| `ecosystem` | `string` | |
| `package_manager` | `string` | |
| `detector` | `string` | |
| `packages` | Array<[`ScanPackage`](#scanpackage)> | |

### `ScanPackage`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `version` | `string` | |
| `scope` | `string` | |
| `purl` | `string` | |
| `id` | `string` | |
| `licenses` | Array<[`LicenseRef`](#licenseref)> | |
| `dependencies` | Array<`string`> | |

