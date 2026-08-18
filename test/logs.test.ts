/**
 * Log parsing, against the shape Claude Desktop actually writes.
 *
 * The samples below are trimmed from a real log file, including the truncation
 * marker the client inserts into long payloads — the detail that decides
 * whether a tool listing can be trusted.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { firstJsonObject, parseServerLog } from "../src/logs.js";

const ts = "2026-05-01T08:17:44.813Z [Demo] [info] ";

/** A complete, untruncated handshake. */
const completeLog = [
  ts + "Initializing server... { metadata: undefined }",
  ts +
    'Message from server: {"result":{"protocolVersion":"2025-11-25",' +
    '"serverInfo":{"name":"demo-mcp-server","version":"1.4.2"}},"jsonrpc":"2.0","id":0}',
  ts +
    'Message from server: {"result":{"tools":[' +
    '{"name":"read_file","description":"Read a file.","inputSchema":{"type":"object",' +
    '"properties":{"path":{"type":"string"}}},"annotations":{"readOnlyHint":true}},' +
    '{"name":"delete_thing","description":"Delete it."}' +
    ']},"jsonrpc":"2.0","id":1}',
  ts +
    'Message from server: {"result":{"prompts":[{"name":"deploy","description":"Ship it.",' +
    '"arguments":[{"name":"branch"}]}]},"jsonrpc":"2.0","id":2}',
].join("\n");

/** The same server, with the tool listing cut short by the client's logger. */
const truncatedLog = [
  ts +
    'Message from server: {"result":{"protocolVersion":"2025-11-25",' +
    '"serverInfo":{"name":"demo-mcp-server","version":"1.4.2","we[2707 chars truncated]...',
  ts +
    'Message from server: {"result":{"tools":[{"name":"read_file","description":"Read a ' +
    'file.[29928 chars truncated]...,"openWorldHint":true}}]},"jsonrpc":"2.0","id":1}',
].join("\n");

describe("firstJsonObject", () => {
  it("reads an object off a prefixed log line", () => {
    const value = firstJsonObject('12:00 [x] Message from server: {"a":1} { metadata: undefined }');
    assert.deepEqual(value, { a: 1 });
  });

  it("is not fooled by braces inside a string", () => {
    const value = firstJsonObject('x {"description":"use {curly} braces","b":2}');
    assert.deepEqual(value, { description: "use {curly} braces", b: 2 });
  });

  it("is not fooled by an escaped quote", () => {
    const value = firstJsonObject('x {"description":"say \\"hi\\" now","b":3}');
    assert.deepEqual(value, { description: 'say "hi" now', b: 3 });
  });

  it("returns undefined when the object never closes", () => {
    assert.equal(firstJsonObject('x {"a":1'), undefined);
  });
});

describe("parseServerLog", () => {
  it("recovers identity, tools and prompts from a complete log", () => {
    const s = parseServerLog(completeLog, "Demo", "claude-desktop", "/logs/demo.log");

    assert.deepEqual(s.serverInfo, { name: "demo-mcp-server", version: "1.4.2" });
    assert.deepEqual(s.tools.map((t) => t.name), ["read_file", "delete_thing"]);
    assert.equal(s.tools[0].annotations?.readOnlyHint, true);
    assert.deepEqual(s.prompts.map((p) => p.name), ["deploy"]);
    assert.equal(s.listingComplete, true);
  });

  /*
   * The client replaces the middle of a long payload with a marker, leaving
   * JSON that cannot be parsed. Treating what survives as the whole listing
   * would run the rules over a fraction of the surface and report it clean.
   */
  it("marks a truncated listing incomplete rather than reporting a short one", () => {
    const s = parseServerLog(truncatedLog, "Demo", "claude-desktop", "/logs/demo.log");

    assert.equal(s.listingComplete, false, "a cut listing must not pass as complete");
    assert.deepEqual(s.tools, [], "no tool may be presented as if fully read");
  });

  it("still recovers identity from a truncated log", () => {
    const s = parseServerLog(truncatedLog, "Demo", "claude-desktop", "/logs/demo.log");
    assert.deepEqual(s.serverInfo, { name: "demo-mcp-server", version: "1.4.2" });
  });

  it("keeps the tool names that survived, for information", () => {
    const s = parseServerLog(truncatedLog, "Demo", "claude-desktop", "/logs/demo.log");
    assert.ok(s.partialToolNames.includes("read_file"));
  });

  it("prefers the most recent listing when a log spans sessions", () => {
    const older = completeLog;
    const newer = [
      ts + 'Message from server: {"result":{"tools":[{"name":"only_this"}]},"jsonrpc":"2.0","id":1}',
    ].join("\n");

    const s = parseServerLog(`${older}\n${newer}`, "Demo", "claude-desktop", "/logs/demo.log");
    assert.deepEqual(s.tools.map((t) => t.name), ["only_this"]);
  });

  it("returns an empty surface for a log with no handshake in it", () => {
    const s = parseServerLog(`${ts}Initializing server...`, "Demo", "claude-desktop", "/l.log");
    assert.deepEqual(s.tools, []);
    assert.equal(s.serverInfo, undefined);
  });
});
