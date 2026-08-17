/**
 * A server that paginates its tool list must be read to the end.
 *
 * `tools/list` may return one page plus a cursor. A client that stops at the
 * first page sees a subset — and for a scanner, tools it never sees are
 * findings it never reports. That failure is silent, which is why it needs a
 * test rather than a glance at the code.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { scanServer } from "../src/scan.js";
import { declared } from "./factories.js";

const TSX = "node_modules/tsx/dist/cli.mjs";

/** Same server, once paginated and once not. */
function fixture(mode: "gitops" | "paged") {
  return declared({
    name: mode,
    command: process.execPath,
    args: [TSX, "fixtures/vulnerable-server/server.ts", mode],
  });
}

describe("paginated listings", () => {
  it("reads every page of a paginated tools/list", async () => {
    const paged = await scanServer(fixture("paged"), { allowSpawn: true, timeoutMs: 60_000 });
    assert.equal(paged.status, "ok", paged.note);
    assert.equal(
      paged.tools.length,
      2,
      "the paged fixture returns one tool per page; both must be collected",
    );
  });

  it("agrees with the same server listing in one page", async () => {
    const [paged, whole] = await Promise.all([
      scanServer(fixture("paged"), { allowSpawn: true, timeoutMs: 60_000 }),
      scanServer(fixture("gitops"), { allowSpawn: true, timeoutMs: 60_000 }),
    ]);

    assert.equal(whole.status, "ok", whole.note);
    assert.deepEqual(
      paged.tools.map((t) => t.name).sort(),
      whole.tools.map((t) => t.name).sort(),
      "pagination must not change which tools are found",
    );
  });
});
