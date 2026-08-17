import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { IMPLEMENTATION, VERSION } from "../src/version.js";

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  name: string;
  version: string;
};

describe("version", () => {
  // Regression: the handshake identity was written out by hand in two files and
  // still said 0.1.0 after the release was bumped to 0.2.0, so mcp-doctor
  // announced the wrong version to every server it connected to — and to
  // clients of its own MCP server.
  it("matches package.json", () => {
    assert.equal(VERSION, manifest.version);
  });

  it("is what the handshake announces", () => {
    assert.equal(IMPLEMENTATION.version, manifest.version);
    assert.equal(IMPLEMENTATION.name, "mcp-doctor");
  });

  it("looks like a semantic version", () => {
    assert.match(VERSION, /^\d+\.\d+\.\d+/);
  });
});
