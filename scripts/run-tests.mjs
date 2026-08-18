#!/usr/bin/env node
/**
 * Run the test suite.
 *
 * `tsx --test test/*.test.ts` looks portable and is not: POSIX shells expand
 * the glob before Node sees it, cmd.exe does not, and Node's own glob support
 * for --test only arrived in Node 22. The combination that fails is therefore
 * Windows on Node 20 — a corner easy to miss without a CI matrix.
 *
 * Listing the files here removes the shell and the Node version from the
 * equation entirely.
 */

import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";

const TEST_DIR = "test";

const files = readdirSync(TEST_DIR)
  .filter((name) => name.endsWith(".test.ts"))
  .sort()
  .map((name) => join(TEST_DIR, name));

if (files.length === 0) {
  console.error(`No *.test.ts files found in ${TEST_DIR}/`);
  process.exit(1);
}

/*
 * Resolve tsx's own entry script rather than the node_modules/.bin shim.
 *
 * On Windows that shim is a .cmd file, and since Node 20.12 spawning a .cmd
 * without a shell fails outright with EINVAL. Running the .mjs through the
 * current Node binary sidesteps shell quoting and platform shims together.
 */
const require = createRequire(import.meta.url);
const tsxPackage = require.resolve("tsx/package.json");
const tsxCli = resolve(dirname(tsxPackage), require("tsx/package.json").bin);

/*
 * One file at a time.
 *
 * Node runs test files in parallel by default, sized to the machine. Two of
 * these files spawn real MCP servers over stdio, and a CI runner has a couple
 * of cores against this laptop's eighteen — enough contention that the
 * handshakes missed their budget on Windows while every other platform passed.
 * The suite is small; determinism is worth more than the seconds.
 */
const result = spawnSync(
  process.execPath,
  [tsxCli, "--test", "--test-concurrency=1", ...files],
  { stdio: "inherit" },
);

if (result.error) {
  console.error(`Could not run ${tsxCli}: ${result.error.message}`);
  process.exit(1);
}

process.exit(result.status ?? 1);
