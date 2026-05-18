## Scan your .NET project

Bomly's `nuget-detector` reads `packages.lock.json` (the central package lockfile for .NET) and produces a full transitive graph with NuGet coordinates. It also accepts `*.deps.json` for runtime-asset graphs and falls back to project XML (`*.csproj`, `*.fsproj`, `*.vbproj`) when no lockfile is present.

```bash
bomly scan --path .
```

## Prerequisites

- A committed `packages.lock.json` for full transitive resolution. Enable with `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` in your project file, then run `dotnet restore --use-lock-file` once.
- For published / built apps, `<assembly>.deps.json` reflects the runtime graph; Bomly will use it if present.
- Project files (`*.csproj`, `*.fsproj`, `*.vbproj`) without a lockfile produce a flat package list (direct deps only).
- For `--install-first`: `dotnet` on `PATH` (Bomly will run `dotnet restore --use-lock-file`).

## Examples

### Fix a direct vulnerability

Bump in `*.csproj`:

```xml
<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
```

`dotnet restore --force-evaluate`. Re-scan.

### Pin a transitive vulnerability

Promote the transitive to a top-level `PackageReference` at the fixed version:

```xml
<PackageReference Include="System.Text.Json" Version="8.0.4" />
```

Or use NuGet's central package management (`Directory.Packages.props`):

```xml
<ItemGroup>
  <PackageVersion Include="System.Text.Json" Version="8.0.4" />
</ItemGroup>
```

`dotnet restore`. Re-scan.

## Limitations

- **No reachability analyzer for .NET today.** `--reachability` produces `not_applicable` for NuGet packages.
- **`packages.config` (old-style)** is parsed but produces only a flat list. Migrate to `PackageReference` for a full graph.
- **Target frameworks** are recorded as metadata; per-TFM reachability is not computed.
- **Native runtime packages** (`runtime.<rid>.native.*`) are tracked as regular packages; advisory matching uses the NuGet ID.
- **Private feeds** require `NuGet.Config` configured locally; Bomly does not authenticate to NuGet feeds.
