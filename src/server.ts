/**
 * mcp-doctor's other face: an MCP server.
 *
 * Everything above this file makes mcp-doctor a *client* that inspects other
 * servers. This file lets an assistant ask the question directly — "what did I
 * just get access to?" — mid-conversation, without leaving the session.
 *
 * Reached through `mcp-doctor serve` rather than a second binary. npx resolves
 * a package to its bin by name, and with two bins it cannot choose, so
 * `npx @tracepoint/mcp-doctor audit` would fail outright. One binary, subcommands
 * underneath it.
 *
 * The tool definitions below are written to pass mcp-doctor's own rules:
 * bounded parameters, honest annotations, descriptions that state behaviour
 * rather than argue for their own selection.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { join } from "node:path";
import { computeCost } from "./cost.js";
import { discover } from "./discover.js";
import { LOCKFILE_NAME, buildLockfile, diffAgainstLock, readLockfile, writeLockfile } from "./lockfile.js";
import { countBySeverity, runRules } from "./rules/index.js";
import { scanAll } from "./scan.js";
import type { Finding } from "./types.js";

const DIRECTORY_PROP = {
  type: "string",
  description: "Project directory to include in the search. Defaults to the working directory.",
  maxLength: 512,
} as const;

const tools: Tool[] = [
  {
    name: "audit_mcp_servers",
    description:
      "Inspect the MCP servers declared in this machine's client config files and " +
      "report security findings, ordered by severity. Reads configuration only; " +
      "set live to true to additionally connect to each server and read its tools.",
    inputSchema: {
      type: "object",
      properties: {
        directory: DIRECTORY_PROP,
        live: {
          type: "boolean",
          description:
            "Connect to declared servers. For local servers this executes them, so it " +
            "is off by default.",
        },
      },
    },
    annotations: {
      title: "Audit MCP servers",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "explain_blast_radius",
    description:
      "Summarise what the currently installed MCP servers could do at worst: which " +
      "credentials they hold, which tools can reach the network, and which pairs of " +
      "tools form a path from local data to an external destination.",
    inputSchema: {
      type: "object",
      properties: { directory: DIRECTORY_PROP },
    },
    annotations: {
      title: "Explain blast radius",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "check_drift",
    description:
      "Compare the current tool definitions against the approved snapshot in " +
      "mcp-doctor.lock.json and report anything that changed since it was written.",
    inputSchema: {
      type: "object",
      properties: {
        directory: DIRECTORY_PROP,
        update: {
          type: "boolean",
          description: "Rewrite the lockfile to accept the current state as approved.",
        },
      },
    },
    annotations: {
      title: "Check for tool definition drift",
      readOnlyHint: false, // `update` writes the lockfile — say so.
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
];

function formatFindings(findings: Finding[]): string {
  if (findings.length === 0) return "No findings.";
  const counts = countBySeverity(findings);
  const header = Object.entries(counts)
    .map(([k, v]) => `${v} ${k}`)
    .join(", ");

  const body = findings
    .map((f) => {
      const where = f.servers?.length ? f.servers.join(" + ") : [f.server, f.tool].filter(Boolean).join(".");
      const lines = [`- **[${f.severity.toUpperCase()}] ${f.title}**`];
      if (where) lines.push(`  - where: ${where} (\`${f.rule}\`)`);
      lines.push(`  - ${f.detail}`);
      if (f.evidence) lines.push(`  - evidence: \`${f.evidence.replace(/\s+/g, " ").slice(0, 200)}\``);
      if (f.remediation) lines.push(`  - fix: ${f.remediation}`);
      return lines.join("\n");
    })
    .join("\n\n");

  return `${header}\n\n${body}`;
}

async function collect(directory: string | undefined, live: boolean) {
  const dir = directory ?? process.cwd();
  const discovery = discover([dir]);
  const scan = await scanAll(discovery, { allowSpawn: live, allowNetwork: live });
  return { dir, scan, findings: runRules(scan), cost: computeCost(scan) };
}

function createServer(): Server {
  const server = new Server(
    { name: "mcp-doctor", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    const directory = typeof args.directory === "string" ? args.directory : undefined;

    try {
      switch (req.params.name) {
        case "audit_mcp_servers": {
          const live = args.live === true;
          const { scan, findings, cost } = await collect(directory, live);
          const text =
            `# MCP audit\n\n` +
            `${scan.discovery.servers.length} declared server(s), ` +
            `${scan.servers.filter((s) => s.status === "ok").length} scanned, ` +
            `${cost.totalTokens} estimated tokens of tool definitions.\n\n` +
            (live
              ? ""
              : "_Configuration-only scan. Pass live: true to read each server's tools._\n\n") +
            formatFindings(findings);
          return { content: [{ type: "text", text }] };
        }

        case "explain_blast_radius": {
          const { scan, findings, cost } = await collect(directory, true);
          const chains = findings.filter((f) => f.rule === "exfiltration-path");
          const secrets = scan.discovery.servers.flatMap((s) =>
            s.envKeys.map((k) => `${s.name}: ${k}`),
          );
          const openWorld = scan.servers.flatMap((s) =>
            s.tools.filter((t) => t.annotations?.openWorldHint === true).map((t) => `${s.name}.${t.name}`),
          );

          const text =
            `# Blast radius\n\n` +
            `## Credentials held by servers\n` +
            (secrets.length ? secrets.map((s) => `- ${s}`).join("\n") : "- none declared") +
            `\n\n## Tools that reach the network\n` +
            (openWorld.length ? openWorld.map((s) => `- ${s}`).join("\n") : "- none") +
            `\n\n## Paths from local data to an external destination\n` +
            (chains.length
              ? chains.map((c) => `- ${c.evidence ?? c.title}`).join("\n")
              : "- none found") +
            `\n\n## Context overhead\n- ${cost.totalTokens} estimated tokens per request\n`;
          return { content: [{ type: "text", text }] };
        }

        case "check_drift": {
          const { dir, scan } = await collect(directory, true);
          const lockPath = join(dir, LOCKFILE_NAME);

          if (args.update === true) {
            writeLockfile(lockPath, buildLockfile(scan));
            return {
              content: [{ type: "text", text: `Lockfile updated: ${lockPath}` }],
            };
          }

          const previous = readLockfile(lockPath);
          if (!previous) {
            return {
              content: [
                {
                  type: "text",
                  text: `No ${LOCKFILE_NAME} in ${dir}. Call check_drift with update: true to record the current state as approved.`,
                },
              ],
            };
          }

          const drift = diffAgainstLock(previous, scan);
          return {
            content: [
              { type: "text", text: `# Drift since ${previous.generatedAt}\n\n${formatFindings(drift)}` },
            ],
          };
        }

        default:
          return {
            content: [{ type: "text", text: `Unknown tool: ${req.params.name}` }],
            isError: true,
          };
      }
    } catch (err) {
      return {
        content: [
          { type: "text", text: `mcp-doctor failed: ${err instanceof Error ? err.message : String(err)}` },
        ],
        isError: true,
      };
    }
  });

  return server;
}

/** Serve over stdio. Returns once the transport closes. */
export async function startServer(): Promise<void> {
  await createServer().connect(new StdioServerTransport());
}
