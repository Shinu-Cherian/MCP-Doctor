#!/usr/bin/env node
/**
 * A remote-style MCP server, served over Streamable HTTP on loopback.
 *
 * Exists so the `--network` code path can be exercised without contacting
 * anyone. Everything stays on 127.0.0.1; no packets leave the machine.
 *
 *   npx tsx fixtures/http-server/server.ts [port]
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { createServer } from "node:http";

const PORT = Number(process.argv[2] ?? 39217);

const tools: Tool[] = [
  {
    // Clean: constrained input, honest annotations.
    name: "list_incidents",
    description: "List open incidents for a project.",
    inputSchema: {
      type: "object",
      properties: { status: { enum: ["open", "resolved"] } },
      required: ["status"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
  {
    // Unbounded URL parameter plus an open-world hint: an outbound sink.
    name: "forward_report",
    description: "Forward an incident report to an external system.",
    inputSchema: {
      type: "object",
      properties: { url: { type: "string" }, body: { type: "string" } },
      required: ["url", "body"],
    },
    annotations: { openWorldHint: true },
  },
];

function buildServer(): Server {
  const server = new Server(
    { name: "incidents-http-mcp", version: "2.1.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => ({
    content: [{ type: "text", text: `[fixture] ${req.params.name} called` }],
  }));
  return server;
}

/** Collect a request body; the transport needs it parsed for POST. */
function readBody(req: import("node:http").IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("error", reject);
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve(undefined);
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
  });
}

const http = createServer(async (req, res) => {
  if (!req.url?.startsWith("/mcp")) {
    res.writeHead(404).end();
    return;
  }

  // Stateless: a fresh server and transport per request, which is the simplest
  // correct arrangement and matches how most hosted MCP servers behave.
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

  res.on("close", () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    const body = req.method === "POST" ? await readBody(req) : undefined;
    await transport.handleRequest(req, res, body);
  } catch (err) {
    if (!res.headersSent) res.writeHead(500).end(String(err));
  }
});

http.listen(PORT, "127.0.0.1", () => {
  console.error(`[fixture] http mcp server on http://127.0.0.1:${PORT}/mcp`);
});
