#!/usr/bin/env node
// Copies the repository LICENSE and NOTICE into the package before it is
// packed, so the published tarball carries them.
//
// They are copied rather than committed here because a second copy in git
// drifts from the originals. `files` in package.json lists them, and
// .gitignore ignores them inside npm/.

"use strict";

const fs = require("node:fs");
const path = require("node:path");

const PACKAGE_DIR = path.join(__dirname, "..");
const REPO_ROOT = path.join(PACKAGE_DIR, "..");

for (const name of ["LICENSE", "NOTICE"]) {
  const from = path.join(REPO_ROOT, name);
  if (!fs.existsSync(from)) {
    console.error(
      `bomly-mcp: ${name} is missing at the repository root. ` +
        "The package must not be published without it.",
    );
    process.exit(1);
  }
  fs.copyFileSync(from, path.join(PACKAGE_DIR, name));
}
