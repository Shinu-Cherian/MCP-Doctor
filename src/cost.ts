/**
 * What your tool definitions cost before you type anything.
 *
 * Every tool a server exposes is serialised into the model's context on every
 * single request. Twelve servers can consume a five-figure token budget that
 * never appears on any dashboard.
 *
 * The count here is an estimate, not a tokenizer. Different models tokenise
 * differently, so a precise number would be precise for exactly one model;
 * the useful signal is the order of magnitude and the ranking between servers.
 */

import type { ScanResult, ServerScan } from "./types.js";

/** Bytes per token, empirically reasonable for JSON + English prose. */
const CHARS_PER_TOKEN = 3.7;

export interface ServerCost {
  server: string;
  toolCount: number;
  estimatedTokens: number;
  /** The single most expensive tool, usually worth looking at. */
  heaviestTool?: { name: string; tokens: number };
}

export interface CostReport {
  totalTokens: number;
  perServer: ServerCost[];
  /** Rough monthly overhead if you send this many messages a day. */
  note: string;
}

function estimate(value: unknown): number {
  return Math.round(JSON.stringify(value ?? "").length / CHARS_PER_TOKEN);
}

function costOfServer(scan: ServerScan): ServerCost {
  let total = 0;
  let heaviest: { name: string; tokens: number } | undefined;

  for (const tool of scan.tools) {
    // What a client actually serialises for each tool.
    const tokens = estimate({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
      annotations: tool.annotations,
    });
    total += tokens;
    if (!heaviest || tokens > heaviest.tokens) heaviest = { name: tool.name, tokens };
  }

  return {
    server: scan.name,
    toolCount: scan.tools.length,
    estimatedTokens: total,
    heaviestTool: heaviest,
  };
}

export function computeCost(result: ScanResult): CostReport {
  const perServer = result.servers
    .filter((s) => s.status === "ok")
    .map(costOfServer)
    .sort((a, b) => b.estimatedTokens - a.estimatedTokens);

  const totalTokens = perServer.reduce((n, s) => n + s.estimatedTokens, 0);

  return {
    totalTokens,
    perServer,
    note:
      `At 50 messages a day this overhead alone is roughly ` +
      `${((totalTokens * 50 * 30) / 1_000_000).toFixed(1)}M tokens a month, ` +
      `paid whether or not any of these tools is used.`,
  };
}
