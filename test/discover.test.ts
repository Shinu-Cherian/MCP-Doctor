import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { discover } from "../src/discover.js";

let dir: string;

before(() => {
  dir = mkdtempSync(join(tmpdir(), "mcp-doctor-test-"));
});

after(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("discover", () => {
  it("reads servers from .mcp.json and normalises stdio entries", () => {
    const project = join(dir, "basic");
    mkdirSync(project, { recursive: true });
    writeFileSync(
      join(project, ".mcp.json"),
      JSON.stringify({
        mcpServers: {
          github: {
            command: "npx",
            args: ["-y", "server-github@1.2.3"],
            env: { GITHUB_TOKEN: "ghp_secret_value" },
          },
        },
      }),
    );

    const result = discover([project]);
    const server = result.servers.find((s) => s.name === "github");

    assert.ok(server, "github server should be discovered");
    assert.equal(server.transport, "stdio");
    assert.equal(server.command, "npx");
    assert.deepEqual(server.args, ["-y", "server-github@1.2.3"]);
  });

  it("records secret names but never secret values", () => {
    const project = join(dir, "secrets");
    mkdirSync(project, { recursive: true });
    writeFileSync(
      join(project, ".mcp.json"),
      JSON.stringify({
        mcpServers: {
          db: { command: "node", env: { PGPASSWORD: "hunter2", DATABASE_URL: "postgres://x" } },
        },
      }),
    );

    const result = discover([project]);
    const server = result.servers.find((s) => s.name === "db");

    assert.ok(server);
    assert.deepEqual(server.envKeys.sort(), ["DATABASE_URL", "PGPASSWORD"]);

    // The whole result is serialised into reports; no value may survive into it.
    const serialised = JSON.stringify(result);
    assert.ok(!serialised.includes("hunter2"), "secret value leaked into discovery result");
    assert.ok(!serialised.includes("postgres://x"), "connection string leaked into result");
  });

  it("detects http transport from an explicit type and from a bare url", () => {
    const project = join(dir, "http");
    mkdirSync(project, { recursive: true });
    writeFileSync(
      join(project, ".mcp.json"),
      JSON.stringify({
        mcpServers: {
          explicit: { type: "http", url: "https://a.example/mcp" },
          implied: { url: "https://b.example/mcp" },
        },
      }),
    );

    const result = discover([project]);
    assert.equal(result.servers.find((s) => s.name === "explicit")?.transport, "http");
    assert.equal(result.servers.find((s) => s.name === "implied")?.transport, "http");
  });

  it("parses VS Code mcp.json with comments and trailing commas", () => {
    const project = join(dir, "vscode");
    mkdirSync(join(project, ".vscode"), { recursive: true });
    writeFileSync(
      join(project, ".vscode", "mcp.json"),
      `{
        // VS Code permits comments here.
        "servers": {
          "sentry": { "type": "http", "url": "https://mcp.sentry.dev/mcp", },
        },
      }`,
    );

    const result = discover([project]);
    assert.ok(
      result.servers.some((s) => s.name === "sentry"),
      "JSON.parse would throw on this file; jsonc-parser must handle it",
    );
  });

  // Regression: Notepad and PowerShell's `Out-File -Encoding utf8` prepend a
  // UTF-8 BOM. It is invisible in editors and made the parser fail at offset 0,
  // so a perfectly valid config was reported as zero servers.
  it("parses a config file that begins with a UTF-8 BOM", () => {
    const project = join(dir, "bom");
    mkdirSync(project, { recursive: true });
    writeFileSync(
      join(project, ".mcp.json"),
      `﻿${JSON.stringify({ mcpServers: { withbom: { command: "node" } } })}`,
      "utf8",
    );

    const result = discover([project]);
    assert.equal(result.errors.length, 0, "a BOM must not be reported as malformed JSON");
    assert.ok(result.servers.some((s) => s.name === "withbom"));
  });

  it("reports malformed config as an error rather than throwing", () => {
    const project = join(dir, "broken");
    mkdirSync(project, { recursive: true });
    writeFileSync(join(project, ".mcp.json"), "{ this is not json");

    const result = discover([project]);
    assert.equal(result.servers.length, 0);
    assert.equal(result.errors.length, 1);
    assert.match(result.errors[0].path, /\.mcp\.json$/);
  });

  it("lists every path it checked, including ones that do not exist", () => {
    const project = join(dir, "empty");
    mkdirSync(project, { recursive: true });

    const result = discover([project]);
    assert.ok(
      result.checkedPaths.some((p) => p.endsWith(join(project, ".mcp.json"))),
      "a missing path must still be reported as checked",
    );
    assert.equal(result.servers.length, 0);
  });

  it("finds servers nested under Claude Code's projects map", () => {
    const project = join(dir, "nested");
    mkdirSync(project, { recursive: true });
    writeFileSync(
      join(project, ".mcp.json"),
      JSON.stringify({
        mcpServers: {},
        projects: {
          "/some/project": { mcpServers: { nested: { command: "node" } } },
        },
      }),
    );

    const result = discover([project]);
    assert.ok(
      result.servers.some((s) => s.name === "nested"),
      "servers declared per-project must not be missed",
    );
  });
});
