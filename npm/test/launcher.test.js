"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const PACKAGE_DIR = path.join(__dirname, "..");
const LAUNCHER = path.join(PACKAGE_DIR, "bin", "bomly-mcp.js");
const VENDOR_DIR = path.join(PACKAGE_DIR, "vendor");

// The launcher execs vendor/bomly. These tests put a shell shim there so they
// can drive shutdown and pass-through behavior without a 90 MB download. A
// real vendored binary (left by a local postinstall) is moved aside and put
// back, so running the suite never destroys someone's working install.
async function withFakeBinary(script, run) {
  const binary = path.join(VENDOR_DIR, "bomly");
  const backup = path.join(VENDOR_DIR, "bomly.test-backup");
  const hadReal = fs.existsSync(binary);

  fs.mkdirSync(VENDOR_DIR, { recursive: true });
  if (hadReal) {
    fs.renameSync(binary, backup);
  }
  fs.writeFileSync(binary, script);
  fs.chmodSync(binary, 0o755);

  try {
    return await run(binary);
  } finally {
    fs.rmSync(binary, { force: true });
    if (hadReal) {
      fs.renameSync(backup, binary);
    }
  }
}

// Same idea for the tests that need vendor/bomly to be absent.
async function withoutBinary(run) {
  const binary = path.join(VENDOR_DIR, "bomly");
  const backup = path.join(VENDOR_DIR, "bomly.test-backup");
  const hadReal = fs.existsSync(binary);

  if (hadReal) {
    fs.renameSync(binary, backup);
  }
  try {
    return await run();
  } finally {
    if (hadReal) {
      fs.renameSync(backup, binary);
    }
  }
}

function runLauncher(args = [], options = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [LAUNCHER, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
      ...options,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("exit", (code, signal) => resolve({ code, signal, stdout, stderr, child }));
    if (options.onSpawn) {
      options.onSpawn(child);
    }
  });
}

test("a missing vendored binary fails with install guidance, not a stack trace", async () => {
  await withoutBinary(async () => {
    const result = await runLauncher();

    assert.equal(result.code, 1);
    assert.match(result.stderr, /Bomly binary is missing/);
    assert.match(result.stderr, /npm install bomly-mcp/);
    // Nothing may reach stdout — an MCP client parses it as JSON-RPC.
    assert.equal(result.stdout, "");
  });
});

test("arguments pass through to the child after `mcp serve`", async () => {
  await withFakeBinary('#!/bin/sh\necho "$@" >&2\n', async () => {
    const result = await runLauncher(["--verbose"]);
    assert.equal(result.stderr.trim(), "mcp serve --verbose");
  });
});

test("stdout stays clean so the JSON-RPC stream is not corrupted", async () => {
  await withFakeBinary('#!/bin/sh\necho \'{"jsonrpc":"2.0"}\'\necho banner >&2\n', async () => {
    const result = await runLauncher();
    assert.equal(result.stdout.trim(), '{"jsonrpc":"2.0"}');
    assert.match(result.stderr, /banner/);
  });
});

test("the child's exit code becomes the wrapper's exit code", async () => {
  await withFakeBinary("#!/bin/sh\nexit 3\n", async () => {
    const result = await runLauncher();
    assert.equal(result.code, 3);
  });
});

test("a child killed by a signal kills the wrapper with the same signal", async () => {
  // The shim deliberately does not trap TERM, so it dies *by* the signal and
  // the wrapper takes its signal branch.
  await withFakeBinary("#!/bin/sh\nwhile true; do sleep 0.05; done\n", async () => {
    const result = await runLauncher([], {
      onSpawn: (child) => setTimeout(() => child.kill("SIGTERM"), 300),
    });

    // This is what the removeListener fix buys. With our own listener still
    // attached, re-raising just re-entered the handler, the event loop then
    // drained, and the wrapper exited 0 — reporting a clean shutdown to
    // whatever supervises it when it had actually been terminated.
    assert.equal(result.signal, "SIGTERM");
    assert.equal(result.code, null);
  });
});

test("a child that exits cleanly on a signal is still a clean exit", async () => {
  await withFakeBinary('#!/bin/sh\ntrap "exit 0" TERM\nwhile true; do sleep 0.05; done\n', async () => {
    const result = await runLauncher([], {
      onSpawn: (child) => setTimeout(() => child.kill("SIGTERM"), 300),
    });

    assert.equal(result.code, 0);
    assert.equal(result.signal, null);
  });
});

test("the packed tarball carries the launcher, installer, and notices", async () => {
  const { execFileSync } = require("node:child_process");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bomly-mcp-pack-"));
  try {
    const json = execFileSync("npm", ["pack", "--dry-run", "--json", PACKAGE_DIR], {
      cwd: dir,
      encoding: "utf8",
      env: { ...process.env, npm_config_loglevel: "error" },
    });
    const files = JSON.parse(json)[0].files.map((f) => f.path);

    for (const required of [
      "package.json",
      "README.md",
      "LICENSE",
      "NOTICE",
      "bin/bomly-mcp.js",
      "scripts/postinstall.js",
    ]) {
      assert.ok(files.includes(required), `packed tarball is missing ${required}`);
    }

    // The binary is fetched at install time; shipping one would defeat the
    // per-platform checksum check.
    assert.ok(!files.some((f) => f.startsWith("vendor/")), "vendor/ must not be packed");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
