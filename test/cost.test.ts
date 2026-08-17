import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { computeCost } from "../src/cost.js";
import { scan, scanResult, tool } from "./factories.js";

describe("cost", () => {
  it("charges more for a verbose tool than a terse one", () => {
    const result = scanResult([
      scan({ name: "terse", tools: [tool({ name: "a", description: "Do a." })] }),
      scan({
        name: "verbose",
        tools: [tool({ name: "b", description: "Do b. ".repeat(200) })],
      }),
    ]);

    const cost = computeCost(result);
    const terse = cost.perServer.find((s) => s.server === "terse")!;
    const verbose = cost.perServer.find((s) => s.server === "verbose")!;

    assert.ok(verbose.estimatedTokens > terse.estimatedTokens);
    assert.equal(cost.totalTokens, terse.estimatedTokens + verbose.estimatedTokens);
  });

  it("ranks servers by cost, most expensive first", () => {
    const result = scanResult([
      scan({ name: "cheap", tools: [tool({ name: "a", description: "x" })] }),
      scan({ name: "dear", tools: [tool({ name: "b", description: "y".repeat(500) })] }),
    ]);
    assert.equal(computeCost(result).perServer[0].server, "dear");
  });

  it("names the heaviest tool on a server", () => {
    const result = scanResult([
      scan({
        name: "s",
        tools: [
          tool({ name: "small", description: "x" }),
          tool({ name: "large", description: "y".repeat(400) }),
        ],
      }),
    ]);
    assert.equal(computeCost(result).perServer[0].heaviestTool?.name, "large");
  });

  it("ignores servers that did not scan", () => {
    const result = scanResult([
      scan({ name: "failed", status: "failed", tools: [tool({ name: "a", description: "x" })] }),
    ]);
    const cost = computeCost(result);
    assert.equal(cost.perServer.length, 0);
    assert.equal(cost.totalTokens, 0);
  });
});
