import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { computeCost } from "../src/cost.js";
import { renderMarkdown, renderTerminal } from "../src/report.js";
import { scan, scanResult, tool } from "./factories.js";

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
