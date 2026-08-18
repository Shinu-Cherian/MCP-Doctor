import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { computeCost } from "../src/cost.js";
import { renderMarkdown, renderTerminal } from "../src/report.js";
import { declared, scan, scanResult, tool } from "./factories.js";

/** Strip ANSI colour so assertions read the text rather than the escape codes. */
function plain(text: string): string {
  return text.replace(new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g"), "");
}

const skipped = scanResult([
  scan({ name: "a", status: "skipped", note: "stdio scan needs --spawn" }),
  scan({ name: "b", status: "skipped", note: "stdio scan needs --spawn" }),
]);

const inspected = scanResult([
  scan({ name: "a", tools: [tool({ name: "read_thing", description: "Read." })] }),
]);

describe("report", () => {
  /*
   * A default run reads configuration only, so it finds configuration problems
   * and none of the tool ones. Presenting that as a bare finding count is a
   * confident partial answer — precisely the failure this tool exists to point
   * at — so the summary has to admit what it did not look at.
   */
  it("says at the top when servers were not inspected", () => {
    const text = plain(renderTerminal(skipped, [], computeCost(skipped)));
    const notice = text.indexOf("2 server(s) not inspected");
    const footer = text.indexOf("Not scanned");

    assert.ok(notice !== -1, "the summary must admit the report is partial");
    assert.ok(footer === -1 || notice < footer, "the notice belongs near the top");
    assert.match(text, /--spawn/);
  });


  /*
   * A server recovered from a log has no command to start and no URL to call,
   * so no flag can reach it. Suggesting one sends the reader off to run
   * something that changes nothing — worse than saying so plainly.
   */
  it("does not offer a flag for a server no flag can reach", () => {
    const fromLog = scanResult([
      scan({
        name: "ext",
        status: "skipped",
        note: "found in claude-desktop logs",
        declared: declared({ name: "ext", transport: "unknown", command: undefined }),
      }),
    ]);

    const text = plain(renderTerminal(fromLog, [], computeCost(fromLog)));
    assert.match(text, /1 server\(s\) not inspected/);
    assert.match(text, /cannot be read from here/);
    assert.ok(!/re-run with --spawn/.test(text), "no flag would help this server");
  });

  it("still offers --spawn when a stdio server was skipped", () => {
    const stdio = scanResult([
      scan({
        name: "local",
        status: "skipped",
        declared: declared({ name: "local", transport: "stdio", command: "node" }),
      }),
    ]);

    const text = plain(renderTerminal(stdio, [], computeCost(stdio)));
    assert.match(text, /re-run with --spawn/);
  });

  it("stays quiet when everything was inspected", () => {
    const text = plain(renderTerminal(inspected, [], computeCost(inspected)));
    assert.ok(!text.includes("not inspected"));
  });

  it("carries the same caveat into the shared markdown report", () => {
    const md = renderMarkdown(skipped, [], computeCost(skipped));
    assert.match(md, /2 server\(s\) were not inspected/);
    assert.match(md, /--spawn/);
  });

  it("leaves the markdown clean when nothing was skipped", () => {
    const md = renderMarkdown(inspected, [], computeCost(inspected));
    assert.ok(!md.includes("were not inspected"));
  });
});
