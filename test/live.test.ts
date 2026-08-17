import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { detectLiveServers, mentionsMcp, selfTree, splitCommand } from "../src/live.js";
import type { RunningProcess } from "../src/types.js";
import { declared } from "./factories.js";

/** A process table with a client at the root, as on a real machine. */
function table(rows: Array<[number, number, string]>): RunningProcess[] {
  return rows.map(([pid, ppid, command]) => ({ pid, ppid, command }));
}

/** A pid that is not in any fixture, so self-exclusion never interferes. */
const NOT_US = 999999;

describe("live process detection", () => {
  describe("splitCommand", () => {
    it("keeps quoted paths containing spaces together", () => {
      assert.deepEqual(splitCommand('"C:\\Program Files\\node.exe" server.js'), [
        "C:\\Program Files\\node.exe",
        "server.js",
      ]);
    });

    it("splits a plain command line on whitespace", () => {
      assert.deepEqual(splitCommand("npx -y some-server"), ["npx", "-y", "some-server"]);
    });
  });

  describe("mentionsMcp", () => {
    it("matches a scoped MCP package", () => {
      assert.ok(mentionsMcp("npx -y @modelcontextprotocol/server-filesystem /tmp"));
    });

    it("matches an mcp-prefixed package name", () => {
      assert.ok(mentionsMcp("uvx mcp-server-git --repo ."));
    });

    // Regression: a checkout at "C:\dev\MCP server\" put MCP into the path of
    // every command run from it, so every one of them was reported.
    it("ignores MCP appearing only in an ancestor directory name", () => {
      assert.ok(
        !mentionsMcp('"node" "C:\\Users\\me\\MCP server\\node_modules\\.bin\\tsx" build.ts'),
        "a directory called 'MCP server' must not make every command an MCP server",
      );
    });

    it("ignores unrelated commands", () => {
      assert.ok(!mentionsMcp("node dist/index.js --watch"));
    });
  });

  describe("selfTree", () => {
    it("covers this process, its launcher and its children", () => {
      const procs = table([
        [100, 1, "claude.exe"],
        [200, 100, "powershell.exe -Command ..."],
        [300, 200, "node mcp-doctor/dist/index.js audit"],
        [400, 300, "node some-child"],
        [500, 100, "node mcp-server-github"],
      ]);

      const tree = selfTree(procs, 300);
      assert.ok(tree.has(300), "self");
      assert.ok(tree.has(200), "launcher");
      assert.ok(tree.has(400), "child");
      assert.ok(!tree.has(100), "must stop at the client");
      assert.ok(!tree.has(500), "a sibling server is not ours");
    });
  });

  describe("detectLiveServers", () => {
    it("finds a server spawned by a client", () => {
      const procs = table([
        [100, 1, "cursor.exe"],
        [200, 100, "npx -y @modelcontextprotocol/server-filesystem C:\\"],
      ]);

      const found = detectLiveServers(procs, [], NOT_US);
      assert.equal(found.length, 1);
      assert.equal(found[0].pid, 200);
      assert.equal(found[0].client, "cursor");
    });

    it("finds a server nested several levels below the client", () => {
      const procs = table([
        [100, 1, "code.exe"],
        [200, 100, "node shim.js"],
        [300, 200, "uvx mcp-server-git"],
      ]);
      const found = detectLiveServers(procs, [], NOT_US);
      assert.deepEqual(
        found.map((f) => f.pid),
        [300],
      );
    });

    it("marks a running server that a config file declared", () => {
      const procs = table([
        [100, 1, "claude.exe"],
        [200, 100, "npx -y @modelcontextprotocol/server-github"],
      ]);
      const config = [
        declared({
          name: "github",
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-github"],
        }),
      ];

      const found = detectLiveServers(procs, config, NOT_US);
      assert.equal(found[0].declaredAs, "github");
      assert.match(found[0].reason, /matches "github"/);
    });

    it("leaves declaredAs empty for a server no config mentions", () => {
      const procs = table([
        [100, 1, "claude.exe"],
        [200, 100, "npx -y some-other-mcp-server"],
      ]);
      const config = [
        declared({ name: "github", command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] }),
      ];

      const found = detectLiveServers(procs, config, NOT_US);
      assert.equal(found.length, 1);
      assert.equal(found[0].declaredAs, undefined);
    });

    it("ignores the shells and helpers a client spawns", () => {
      const procs = table([
        [100, 1, "claude.exe"],
        [200, 100, "powershell.exe -NoProfile -Command Get-Date"],
        [300, 100, "C:\\Program Files\\Git\\bin\\bash.exe -c ls"],
        [400, 100, "node C:\\proj\\mcp thing\\node_modules\\.bin\\eslint ."],
      ]);
      assert.deepEqual(detectLiveServers(procs, [], NOT_US), []);
    });

    it("ignores the client's own renderer processes", () => {
      const procs = table([
        [100, 1, "claude.exe"],
        [200, 100, "claude.exe --type=renderer --mcp-thing"],
      ]);
      assert.deepEqual(detectLiveServers(procs, [], NOT_US), []);
    });

    it("says nothing about ordinary desktop software", () => {
      const procs = table([
        [100, 1, "chrome.exe"],
        [200, 100, "chrome.exe --type=renderer"],
        [300, 1, "explorer.exe"],
        [400, 1, "node C:\\work\\api\\server.js"],
      ]);
      assert.deepEqual(detectLiveServers(procs, [], NOT_US), []);
    });

    it("never reports itself", () => {
      const procs = table([
        [100, 1, "claude.exe"],
        [200, 100, "node C:\\dev\\MCP server\\dist\\index.js audit"],
      ]);
      // Running as pid 200 — the tool must not appear in its own report.
      assert.deepEqual(detectLiveServers(procs, [], 200), []);
    });
  });
});
