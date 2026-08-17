/**
 * Exercises mcp-doctor's own MCP server end to end.
 *
 * The tools were listed and their definitions checked, but never actually
 * called — a handler that throws would have looked identical from the outside.
 */

import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

/**
 * Spawning a server, compiling TypeScript on the fly and completing a stdio
 * handshake is slow on a cold CI runner — Windows especially. Without an
 * explicit budget a slow start looks like a hang rather than a failure.
 */
const SPAWN_TIMEOUT_MS = 120_000;

let client: Client;

/** Pull the text out of a tool result. */
function textOf(result: unknown): string {
  const content = (result as { content?: Array<{ type: string; text?: string }> }).content ?? [];
  return content
    .filter((c) => c.type === "text")
    .map((c) => c.text ?? "")
    .join("\n");
}

function isError(result: unknown): boolean {
  return (result as { isError?: boolean }).isError === true;
}

before(async () => {
  client = new Client({ name: "server-tools-test", version: "0.0.0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: ["node_modules/tsx/dist/cli.mjs", "src/index.ts", "serve"],
      stderr: "ignore",
    }),
  );
}, { timeout: SPAWN_TIMEOUT_MS });

after(async () => {
  await client.close().catch(() => {});
});

describe("mcp-doctor as an MCP server", () => {
  it("advertises exactly the three documented tools", { timeout: SPAWN_TIMEOUT_MS }, async () => {
    const { tools } = await client.listTools();
    assert.deepEqual(
      tools.map((t) => t.name).sort(),
      ["audit_mcp_servers", "check_drift", "explain_blast_radius"],
    );
  });

  it("runs audit_mcp_servers against a directory", { timeout: SPAWN_TIMEOUT_MS }, async () => {
    const result = await client.callTool({
      name: "audit_mcp_servers",
      arguments: { directory: "fixtures/vulnerable-project" },
    });

    assert.ok(!isError(result), "the handler must not fail");
    const text = textOf(result);
    assert.match(text, /# MCP audit/);
    assert.match(text, /declared server/);
    // Config-only by default, so it must say the deeper scan was not performed.
    assert.match(text, /live: true/);
  });

  it("reports findings when asked to connect", { timeout: SPAWN_TIMEOUT_MS }, async () => {
    const result = await client.callTool({
      name: "audit_mcp_servers",
      arguments: { directory: "fixtures/vulnerable-project", live: true },
    });

    assert.ok(!isError(result));
    const text = textOf(result);
    assert.match(text, /tool-poisoning|annotation-lie/, "should surface real findings");
  });

  it("runs explain_blast_radius", { timeout: SPAWN_TIMEOUT_MS }, async () => {
    const result = await client.callTool({
      name: "explain_blast_radius",
      arguments: { directory: "fixtures/vulnerable-project" },
    });

    assert.ok(!isError(result));
    const text = textOf(result);
    assert.match(text, /# Blast radius/);
    assert.match(text, /Credentials held by servers/);
    assert.match(text, /Tools that reach the network/);
  });

  it("reports a missing lockfile rather than failing", { timeout: SPAWN_TIMEOUT_MS }, async () => {
    const result = await client.callTool({
      name: "check_drift",
      arguments: { directory: "fixtures/vulnerable-project" },
    });

    assert.ok(!isError(result));
    assert.match(textOf(result), /No mcp-doctor\.lock\.json|Drift since/);
  });

  it("returns an error for an unknown tool rather than crashing", { timeout: SPAWN_TIMEOUT_MS }, async () => {
    const result = await client.callTool({ name: "no_such_tool", arguments: {} });
    assert.ok(isError(result));
    assert.match(textOf(result), /Unknown tool/);
  });
});
