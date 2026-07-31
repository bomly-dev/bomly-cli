#!/usr/bin/env node
// Downloads the Bomly CLI release archive that matches this package version,
// verifies it against the release's SHA256SUMS, and unpacks the `bomly`
// binary into vendor/. bin/bomly-mcp.js then execs that binary.
//
// The download is verified or it fails. There is no unverified fallback.

"use strict";

const { createHash } = require("node:crypto");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const pkg = require("../package.json");

const ROOT = path.join(__dirname, "..");
const VENDOR_DIR = path.join(ROOT, "vendor");
const RELEASE_BASE = "https://github.com/bomly-dev/bomly-cli/releases/download";

// Same names GoReleaser writes: bomly_<version>_<goos>_<goarch>.<tar.gz|zip>.
const GOOS = { darwin: "darwin", linux: "linux", win32: "windows" };
const GOARCH = { x64: "amd64", arm64: "arm64" };

function fail(message) {
  console.error(`bomly-mcp: ${message}`);
  process.exit(1);
}

// Throws rather than exiting so it stays testable; main() turns the throw
// into the user-facing message.
function resolveTarget(platform, arch) {
  const goos = GOOS[platform];
  const goarch = GOARCH[arch];
  if (!goos || !goarch) {
    throw new Error(
      `no Bomly release build for ${platform}/${arch}. ` +
        "Install the CLI another way (https://github.com/bomly-dev/bomly-cli/blob/main/docs/INSTALLATION.md) " +
        "and point your MCP client at `bomly mcp serve`.",
    );
  }
  const ext = goos === "windows" ? "zip" : "tar.gz";
  return { goos, goarch, ext, binary: goos === "windows" ? "bomly.exe" : "bomly" };
}

// Same names GoReleaser writes.
function archiveNameFor(version, goos, goarch, ext) {
  return `bomly_${version}_${goos}_${goarch}.${ext}`;
}

async function download(url) {
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok) {
    fail(`GET ${url} returned HTTP ${response.status}`);
  }
  return Buffer.from(await response.arrayBuffer());
}

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

// SHA256SUMS is `<hex>  <filename>` per line, as produced by GoReleaser.
function expectedSum(sums, filename) {
  for (const line of sums.split("\n")) {
    const [hex, name] = line.trim().split(/\s+/);
    if (name === filename) {
      return hex;
    }
  }
  return null;
}

// Written to disk and invoked with -File so the paths arrive as real argv
// entries. Interpolating them into a -Command string breaks on any path
// holding an apostrophe (C:\Users\O'Brien\...) and would let a path influence
// the command itself.
const EXPAND_PS1 = `param(
  [Parameter(Mandatory=$true)][string]$Archive,
  [Parameter(Mandatory=$true)][string]$Destination
)
$ErrorActionPreference = 'Stop'
Expand-Archive -LiteralPath $Archive -DestinationPath $Destination -Force
`;

function unpack(archivePath, destination, ext) {
  if (ext === "zip") {
    // PowerShell ships with every supported Windows version; `tar` does too on
    // Windows 10 1803+, but Expand-Archive is the safer floor for zip.
    const scriptPath = path.join(destination, "expand.ps1");
    fs.writeFileSync(scriptPath, EXPAND_PS1);
    execFileSync(
      "powershell",
      [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        scriptPath,
        "-Archive",
        archivePath,
        "-Destination",
        destination,
      ],
      { stdio: "inherit" },
    );
    return;
  }
  execFileSync("tar", ["-xzf", archivePath, "-C", destination], { stdio: "inherit" });
}

// The release archive carries LICENSE, NOTICE, and a licenses/ tree of
// third-party license texts. Vendoring the binary without them would
// redistribute Bomly and its bundled components with the notices stripped.
function copyNotices(staging, destination) {
  for (const entry of ["LICENSE", "NOTICE", "licenses"]) {
    const from = path.join(staging, entry);
    if (fs.existsSync(from)) {
      fs.cpSync(from, path.join(destination, entry), { recursive: true });
    }
  }
}

async function main() {
  if (process.env.BOMLY_MCP_SKIP_DOWNLOAD === "1") {
    console.error("bomly-mcp: BOMLY_MCP_SKIP_DOWNLOAD=1, skipping binary download.");
    return;
  }

  const version = process.env.BOMLY_MCP_VERSION || pkg.version;
  const { ext, goos, goarch, binary } = resolveTarget(process.platform, process.arch);
  const archiveName = archiveNameFor(version, goos, goarch, ext);
  const tag = `v${version}`;

  const sums = (await download(`${RELEASE_BASE}/${tag}/SHA256SUMS`)).toString("utf8");
  const expected = expectedSum(sums, archiveName);
  if (!expected) {
    fail(`${archiveName} is not listed in the SHA256SUMS for ${tag}`);
  }

  const archive = await download(`${RELEASE_BASE}/${tag}/${archiveName}`);
  const actual = sha256(archive);
  if (actual !== expected) {
    fail(
      `checksum mismatch for ${archiveName}\n` +
        `  expected ${expected}\n` +
        `  actual   ${actual}\n` +
        "Refusing to install. Please report this at https://github.com/bomly-dev/bomly-cli/issues.",
    );
  }

  const staging = fs.mkdtempSync(path.join(os.tmpdir(), "bomly-mcp-"));
  try {
    const archivePath = path.join(staging, archiveName);
    fs.writeFileSync(archivePath, archive);
    unpack(archivePath, staging, ext);

    const extracted = path.join(staging, binary);
    if (!fs.existsSync(extracted)) {
      fail(`${archiveName} did not contain ${binary}`);
    }

    fs.mkdirSync(VENDOR_DIR, { recursive: true });
    const installed = path.join(VENDOR_DIR, binary);
    fs.copyFileSync(extracted, installed);
    if (goos !== "windows") {
      fs.chmodSync(installed, 0o755);
    }
    copyNotices(staging, VENDOR_DIR);
    console.error(`bomly-mcp: installed bomly ${version} (${goos}/${goarch}), checksum verified.`);
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

if (require.main === module) {
  main().catch((error) => fail(error && error.message ? error.message : String(error)));
}

// Exported for test/. Everything here is pure or filesystem-local; the
// network path is exercised end to end by installing a packed tarball.
module.exports = { resolveTarget, archiveNameFor, expectedSum, sha256, unpack, copyNotices };
