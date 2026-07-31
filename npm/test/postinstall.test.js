"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const {
  resolveTarget,
  archiveNameFor,
  expectedSum,
  sha256,
  unpack,
  copyNotices,
} = require("../scripts/postinstall.js");

function scratch() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bomly-mcp-test-"));
}

test("platform mapping covers every published release build", () => {
  const cases = [
    ["darwin", "arm64", "darwin", "arm64", "tar.gz", "bomly"],
    ["darwin", "x64", "darwin", "amd64", "tar.gz", "bomly"],
    ["linux", "arm64", "linux", "arm64", "tar.gz", "bomly"],
    ["linux", "x64", "linux", "amd64", "tar.gz", "bomly"],
    ["win32", "arm64", "windows", "arm64", "zip", "bomly.exe"],
    ["win32", "x64", "windows", "amd64", "zip", "bomly.exe"],
  ];

  for (const [platform, arch, goos, goarch, ext, binary] of cases) {
    assert.deepEqual(resolveTarget(platform, arch), { goos, goarch, ext, binary });
  }
});

test("unsupported platforms throw with a usable next step", () => {
  for (const [platform, arch] of [
    ["freebsd", "x64"],
    ["linux", "ia32"],
    ["linux", "riscv64"],
  ]) {
    assert.throws(() => resolveTarget(platform, arch), (error) => {
      assert.match(error.message, /no Bomly release build/);
      assert.match(error.message, /INSTALLATION\.md/);
      return true;
    });
  }
});

test("archive names match what GoReleaser publishes", () => {
  assert.equal(
    archiveNameFor("0.21.1", "darwin", "arm64", "tar.gz"),
    "bomly_0.21.1_darwin_arm64.tar.gz",
  );
  assert.equal(
    archiveNameFor("0.21.1", "windows", "amd64", "zip"),
    "bomly_0.21.1_windows_amd64.zip",
  );
});

test("checksum lookup picks the exact filename out of SHA256SUMS", () => {
  // Real shape: two spaces, and names that are prefixes of one another.
  const sums = [
    "aaaa  bomly-lite_0.21.1_linux_amd64.tar.gz",
    "bbbb  bomly_0.21.1_linux_amd64.tar.gz",
    "cccc  bomly_0.21.1_linux_arm64.tar.gz",
    "",
  ].join("\n");

  assert.equal(expectedSum(sums, "bomly_0.21.1_linux_amd64.tar.gz"), "bbbb");
  assert.equal(expectedSum(sums, "bomly-lite_0.21.1_linux_amd64.tar.gz"), "aaaa");
});

test("checksum lookup returns null when the archive is absent", () => {
  const sums = "aaaa  bomly_0.21.1_linux_amd64.tar.gz\n";

  // A missing entry must not silently pass as a match — main() treats null as
  // fatal, which is what stops an unverified archive from ever being unpacked.
  assert.equal(expectedSum(sums, "bomly_0.21.1_darwin_arm64.tar.gz"), null);
  assert.equal(expectedSum("", "bomly_0.21.1_linux_amd64.tar.gz"), null);
});

test("sha256 detects a single flipped byte", () => {
  const good = Buffer.from("bomly release archive");
  const tampered = Buffer.from("bomly release archivf");

  assert.equal(sha256(good), crypto.createHash("sha256").update(good).digest("hex"));
  assert.notEqual(sha256(good), sha256(tampered));
});

test("unpack extracts the binary from a tar.gz the way the release ships it", { skip: process.platform === "win32" }, () => {
  const dir = scratch();
  try {
    const source = path.join(dir, "src");
    fs.mkdirSync(path.join(source, "licenses"), { recursive: true });
    fs.writeFileSync(path.join(source, "bomly"), "#!/bin/sh\necho bomly\n");
    fs.writeFileSync(path.join(source, "LICENSE"), "Apache-2.0\n");
    fs.writeFileSync(path.join(source, "NOTICE"), "notice\n");
    fs.writeFileSync(path.join(source, "licenses", "syft.txt"), "syft license\n");

    const archive = path.join(dir, "bomly_0.21.1_linux_amd64.tar.gz");
    execFileSync("tar", ["-czf", archive, "-C", source, "."]);

    const out = path.join(dir, "out");
    fs.mkdirSync(out);
    unpack(archive, out, "tar.gz");

    assert.ok(fs.existsSync(path.join(out, "bomly")));
    assert.ok(fs.existsSync(path.join(out, "LICENSE")));
    assert.ok(fs.existsSync(path.join(out, "licenses", "syft.txt")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("license and notice files travel with the vendored binary", () => {
  const dir = scratch();
  try {
    const staging = path.join(dir, "staging");
    const vendor = path.join(dir, "vendor");
    fs.mkdirSync(path.join(staging, "licenses"), { recursive: true });
    fs.mkdirSync(vendor);
    fs.writeFileSync(path.join(staging, "LICENSE"), "Apache-2.0\n");
    fs.writeFileSync(path.join(staging, "NOTICE"), "notice\n");
    fs.writeFileSync(path.join(staging, "licenses", "grype.txt"), "grype license\n");

    copyNotices(staging, vendor);

    assert.equal(fs.readFileSync(path.join(vendor, "LICENSE"), "utf8"), "Apache-2.0\n");
    assert.equal(fs.readFileSync(path.join(vendor, "NOTICE"), "utf8"), "notice\n");
    assert.equal(
      fs.readFileSync(path.join(vendor, "licenses", "grype.txt"), "utf8"),
      "grype license\n",
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("copyNotices tolerates an archive that omits them", () => {
  const dir = scratch();
  try {
    const staging = path.join(dir, "staging");
    const vendor = path.join(dir, "vendor");
    fs.mkdirSync(staging);
    fs.mkdirSync(vendor);

    assert.doesNotThrow(() => copyNotices(staging, vendor));
    assert.deepEqual(fs.readdirSync(vendor), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
