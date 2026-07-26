#!/usr/bin/env node
// Starts the Bomly MCP server over stdio.
//
// This process must stay transparent: stdout carries the JSON-RPC stream and
// nothing else. Diagnostics go to stderr, which is where `bomly mcp serve`
// already writes its startup banner.

"use strict";

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const binary = process.platform === "win32" ? "bomly.exe" : "bomly";
const vendored = path.join(__dirname, "..", "vendor", binary);

if (!fs.existsSync(vendored)) {
  console.error(
    "bomly-mcp: the Bomly binary is missing. Reinstall the package so its postinstall step can run:\n" +
      "  npm install bomly-mcp\n" +
      "Or install the CLI directly and run `bomly mcp serve` instead:\n" +
      "  https://github.com/bomly-dev/bomly-cli/blob/main/docs/INSTALLATION.md",
  );
  process.exit(1);
}

const child = spawn(vendored, ["mcp", "serve", ...process.argv.slice(2)], {
  stdio: "inherit",
});

child.on("error", (error) => {
  console.error(`bomly-mcp: could not start ${vendored}: ${error.message}`);
  process.exit(1);
});

// Forward the signals an MCP client uses to stop a stdio server, so the child
// shuts down with us rather than being orphaned.
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => child.kill(signal));
}

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
