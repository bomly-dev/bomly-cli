param(
  [string]$Version = $env:BOMLY_VERSION,
  [ValidateSet("bomly", "bomly-lite")]
  [string]$Binary = $(if ($env:BOMLY_BINARY) { $env:BOMLY_BINARY } else { "bomly" }),
  [string]$InstallDir = $(if ($env:BOMLY_INSTALL_DIR) { $env:BOMLY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Bomly\bin" }),
  [string]$Repo = $(if ($env:BOMLY_REPO) { $env:BOMLY_REPO } else { "bomly-dev/bomly-cli" })
)

$ErrorActionPreference = "Stop"

# Testing/air-gapped seam: when BOMLY_INSTALL_ARCHIVE points at a local copy
# of a release .zip, install from it directly and skip version resolution,
# download, and checksum verification. The bypass applies only when the
# variable is explicitly set — normal installs always download and verify the
# archive against the release's SHA256SUMS.
$LocalArchive = $env:BOMLY_INSTALL_ARCHIVE

if (-not [string]::IsNullOrWhiteSpace($LocalArchive)) {
  if (-not (Test-Path -Path $LocalArchive -PathType Leaf)) {
    throw "BOMLY_INSTALL_ARCHIVE '$LocalArchive' is not a file."
  }
  Write-Host "notice: BOMLY_INSTALL_ARCHIVE is set; installing from $LocalArchive without download or checksum verification."
  if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = "local"
  }
} else {
  if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = "latest"
  }

  if ($Version -eq "latest") {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $release.tag_name
  }

  if ([string]::IsNullOrWhiteSpace($Version)) {
    throw "Could not resolve Bomly version."
  }
}

$tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid()))

try {
  if (-not [string]::IsNullOrWhiteSpace($LocalArchive)) {
    $archive = Split-Path -Leaf $LocalArchive
    $archivePath = $LocalArchive
  } else {
    $AssetVersion = $Version -replace "^v", ""

    $arch = switch ((Get-CimInstance Win32_OperatingSystem).OSArchitecture) {
      { $_ -match "ARM64" } { "arm64"; break }
      default { "amd64" }
    }

    $archive = "${Binary}_${AssetVersion}_windows_${arch}.zip"
    $baseUrl = "https://github.com/$Repo/releases/download/$Version"
    $archivePath = Join-Path $tmp.FullName $archive
    $sumsPath = Join-Path $tmp.FullName "SHA256SUMS"
    Invoke-WebRequest -Uri "$baseUrl/$archive" -OutFile $archivePath
    Invoke-WebRequest -Uri "$baseUrl/SHA256SUMS" -OutFile $sumsPath

    $expected = (Select-String -Path $sumsPath -Pattern "\s+$([regex]::Escape($archive))$").Line.Split(" ")[0].ToLowerInvariant()
    $actual = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
      throw "Checksum mismatch for $archive."
    }
  }

  Expand-Archive -Path $archivePath -DestinationPath $tmp.FullName -Force
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  Copy-Item -Path (Join-Path $tmp.FullName "$Binary.exe") -Destination (Join-Path $InstallDir "bomly.exe") -Force

  # License and notice files from the archive persist in a doc subfolder of
  # the install directory. Older archives may not carry them; warn, don't fail.
  $docDir = Join-Path $InstallDir "doc"
  New-Item -ItemType Directory -Path $docDir -Force | Out-Null
  foreach ($doc in @("LICENSE", "NOTICE")) {
    $docSource = Join-Path $tmp.FullName $doc
    if (Test-Path $docSource) {
      Copy-Item -Path $docSource -Destination (Join-Path $docDir $doc) -Force
    } else {
      Write-Warning "$doc not found in $archive; skipping."
    }
  }
  $licensesSource = Join-Path $tmp.FullName "licenses"
  if (Test-Path $licensesSource) {
    $licensesDest = Join-Path $docDir "licenses"
    if (Test-Path $licensesDest) {
      Remove-Item -Recurse -Force $licensesDest
    }
    Copy-Item -Recurse -Path $licensesSource -Destination $licensesDest
  } else {
    Write-Warning "licenses directory not found in $archive; skipping."
  }

  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if (($userPath -split ";") -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
    Write-Host "Added $InstallDir to your user PATH. Open a new shell before running bomly."
  }

  Write-Host "Installed $Binary $Version to $(Join-Path $InstallDir "bomly.exe")"
}
finally {
  Remove-Item -Recurse -Force $tmp.FullName
}
