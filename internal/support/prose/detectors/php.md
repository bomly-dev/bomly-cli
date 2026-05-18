## Scan your PHP project

Bomly's `composer-detector` reads `composer.lock` (preferred) or `vendor/composer/installed.json` (when only a `vendor/` directory is committed) and produces a full transitive graph with Packagist coordinates.

```bash
bomly scan --path .
```

## Prerequisites

- A committed `composer.lock` for full transitive resolution. The detector handles Composer 2.x lockfiles.
- If only `vendor/composer/installed.json` is present (no lockfile), the detector reads that file directly. Both produce equivalent graph data.
- No PHP or Composer installation is required to scan — the lockfile is parsed directly.
- For `--install-first`: `composer` on `PATH` (Bomly will run `composer install --no-dev` or `composer install` depending on `--scope`).

## Examples

### Fix a direct vulnerability

Bump in `composer.json`:

```json
{
  "require": {
    "symfony/http-foundation": "^7.1.4"
  }
}
```

Re-lock: `composer update symfony/http-foundation`. Re-scan.

### Pin a transitive vulnerability

Add the transitive package to `require` at the top level with the fixed version:

```json
{
  "require": {
    "guzzlehttp/guzzle": ">=7.9.0"
  }
}
```

`composer update guzzlehttp/guzzle`. Re-scan.

## Limitations

- **No reachability analyzer for PHP today.** `--reachability` produces `not_applicable` for Composer packages.
- **`pear`-installed packages** are detected by Syft, not by `composer-detector`. PEAR is in maintenance; expect coverage to track Syft's PEAR cataloger.
- **`platform` requirements** (`php`, `ext-*`) are recorded as metadata but not turned into graph edges.
- **Path repositories** (`type: path` in `composer.json`) are recorded with their resolved version; internal dependencies of the local package come from the local checkout.
- **VCS repositories** with branch refs are tracked by the resolved reference; advisory matching uses the version Composer records.
