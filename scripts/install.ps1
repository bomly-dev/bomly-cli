param(
  [string]$Version = $env:BOMLY_VERSION,
  [ValidateSet("bomly", "bomly-lite")]
  [string]$Binary = $(if ($env:BOMLY_BINARY) { $env:BOMLY_BINARY } else { "bomly" }),
  [string]$InstallDir = $(if ($env:BOMLY_INSTALL_DIR) { $env:BOMLY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Bomly\bin" }),
  [string]$Repo = $(if ($env:BOMLY_REPO) { $env:BOMLY_REPO } else { "bomly-dev/bomly-cli" })
)

$ErrorActionPreference = "Stop"

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

$arch = switch ((Get-CimInstance Win32_OperatingSystem).OSArchitecture) {
  { $_ -match "ARM64" } { "arm64"; break }
  default { "amd64" }
}

$archive = "${Binary}_${Version}_windows_${arch}.zip"
$baseUrl = "https://github.com/$Repo/releases/download/$Version"
$tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid()))

try {
  $archivePath = Join-Path $tmp.FullName $archive
  $sumsPath = Join-Path $tmp.FullName "SHA256SUMS"
  Invoke-WebRequest -Uri "$baseUrl/$archive" -OutFile $archivePath
  Invoke-WebRequest -Uri "$baseUrl/SHA256SUMS" -OutFile $sumsPath

  $expected = (Select-String -Path $sumsPath -Pattern "\s+$([regex]::Escape($archive))$").Line.Split(" ")[0].ToLowerInvariant()
  $actual = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($expected -ne $actual) {
    throw "Checksum mismatch for $archive."
  }

  Expand-Archive -Path $archivePath -DestinationPath $tmp.FullName -Force
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  Copy-Item -Path (Join-Path $tmp.FullName "$Binary.exe") -Destination (Join-Path $InstallDir "bomly.exe") -Force

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
