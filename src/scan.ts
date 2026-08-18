/**
 * Stage 2: connect to declared servers and read what they actually expose.
 *
 * Two safety rules shape this file:
 *
 * 1. Scanning a stdio server means EXECUTING it. That is the thing we are
 *    trying to protect the user from, so spawning is opt-in (`allowSpawn`),
 *    never the default.
 *
 * 2. We do not forward the user's real secrets to a server just to read its
 *    menu. Most servers list tools fine without credentials; the ones that
 *    refuse get reported as failed rather than silently handed a token.
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { findLiveServers } from "./live.js";
import { readClientLogs } from "./logs.js";
import { IMPLEMENTATION } from "./version.js";
import {
  CreateMessageRequestSchema,
  ElicitRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type {
  DeclaredServer,
  DiscoveryResult,
  PromptDef,
  ResourceDef,
  ScanResult,
  ServerCapabilities,
  LoggedServer,
  LogSummary,
  ResourceTemplateDef,
  ServerScan,
  ToolDef,
  UnsolicitedRequest,
} from "./types.js";

export interface ScanOptions {
  /** Read client logs for servers config never mentions. Read-only; on by default. */
  readLogs?: boolean;
  /** Compare the process table against the config. Read-only; on by default. */
  checkLive?: boolean;
  /** Run local stdio servers. Off by default — see rule 1 above. */
  allowSpawn?: boolean;
  /** Contact remote HTTP servers. Off by default: it reveals you to them. */
  allowNetwork?: boolean;
  /** Pass the current environment through to spawned servers. */
  forwardEnv?: boolean;
  /** Per-server budget for handshake + listing. */
  timeoutMs?: number;
}

const DEFAULTS: Required<ScanOptions> = {
  readLogs: true,
  checkLive: true,
  allowSpawn: false,
  allowNetwork: false,
  forwardEnv: false,
  timeoutMs: 15_000,
};

/** Is this command resolvable on PATH, or a file that exists? */
function commandExists(command: string): boolean {
  if (command.includes("/") || command.includes("\\")) return existsSync(command);
  const probe = process.platform === "win32" ? "where" : "which";
  const result = spawnSync(probe, [command], { stdio: "ignore", shell: false });
  return result.status === 0;
}

/**
 * Turn a transport failure into something a user can act on.
 *
 * Node reports every connection problem as "fetch failed" and hides the real
 * reason in `cause`, which tells the reader nothing about whether the server is
 * down, the host is wrong, or a proxy ate the request.
 */
function describeError(err: unknown, server: DeclaredServer): string {
  const message = err instanceof Error ? err.message : String(err);
  const cause = err instanceof Error ? (err.cause as { code?: string } | undefined) : undefined;
  const target = server.url ?? server.command ?? "the server";

  // A stdio server whose binary is missing dies before it can speak the
  // protocol, and the SDK reports only "Connection closed". Checking the
  // command here — on the failure path, so it costs nothing normally — turns
  // that into something the user can fix.
  if (server.transport === "stdio" && server.command && !commandExists(server.command)) {
    return `command not found: ${server.command}`;
  }

  switch (cause?.code) {
    case "ECONNREFUSED":
      return `nothing is listening at ${target}`;
    case "ENOTFOUND":
      return `host not found for ${target}`;
    case "ETIMEDOUT":
    case "UND_ERR_CONNECT_TIMEOUT":
      return `timed out connecting to ${target}`;
    case "CERT_HAS_EXPIRED":
    case "UNABLE_TO_VERIFY_LEAF_SIGNATURE":
    case "DEPTH_ZERO_SELF_SIGNED_CERT":
      return `TLS certificate rejected for ${target} (${cause.code})`;
    case "ENOENT":
      return `command not found: ${server.command}`;
    default:
      return cause?.code ? `${message} (${cause.code})` : message;
  }
}

/** Reject if a promise outruns its budget, so one hung server can't stall a scan. */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

function buildTransport(server: DeclaredServer, opts: Required<ScanOptions>): Transport {
  if (server.transport === "stdio") {
    if (!server.command) throw new Error("stdio server has no command");
    return new StdioClientTransport({
      command: server.command,
      args: server.args ?? [],
      // Without forwardEnv the child gets only what the SDK considers safe
      // defaults (PATH and friends) — no tokens from this process.
      env: opts.forwardEnv ? (process.env as Record<string, string>) : undefined,
      stderr: "ignore",
    });
  }

  if (server.transport === "http") {
    if (!server.url) throw new Error("http server has no url");
    return new StreamableHTTPClientTransport(new URL(server.url));
  }

  throw new Error(`unsupported transport: ${server.transport}`);
}

/** MCP paginates list results; walk every page or we under-report tool counts. */
async function listAllTools(client: Client): Promise<ToolDef[]> {
  const out: ToolDef[] = [];
  let cursor: string | undefined;
  do {
    const page = await client.listTools(cursor ? { cursor } : {});
    for (const t of page.tools) {
      out.push({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema as Record<string, unknown> | undefined,
        outputSchema: t.outputSchema as Record<string, unknown> | undefined,
        annotations: t.annotations,
      });
    }
    cursor = page.nextCursor;
  } while (cursor);
  return out;
}

async function listAllResources(client: Client): Promise<ResourceDef[]> {
  const out: ResourceDef[] = [];
  let cursor: string | undefined;
  do {
    const page = await client.listResources(cursor ? { cursor } : {});
    for (const r of page.resources) {
      out.push({ uri: r.uri, name: r.name, description: r.description, mimeType: r.mimeType });
    }
    cursor = page.nextCursor;
  } while (cursor);
  return out;
}

/**
 * Templates live behind a separate method from concrete resources, and a server
 * may expose only templates. Skipping this call is how a scanner reports
 * "no resources" for a server that can serve the entire filesystem.
 */
async function listAllResourceTemplates(client: Client): Promise<ResourceTemplateDef[]> {
  const out: ResourceTemplateDef[] = [];
  let cursor: string | undefined;
  do {
    const page = await client.listResourceTemplates(cursor ? { cursor } : {});
    for (const t of page.resourceTemplates) {
      out.push({
        uriTemplate: t.uriTemplate,
        name: t.name,
        description: t.description,
        mimeType: t.mimeType,
      });
    }
    cursor = page.nextCursor;
  } while (cursor);
  return out;
}

async function listAllPrompts(client: Client): Promise<PromptDef[]> {
  const out: PromptDef[] = [];
  let cursor: string | undefined;
  do {
    const page = await client.listPrompts(cursor ? { cursor } : {});
    for (const p of page.prompts) {
      out.push({
        name: p.name,
        description: p.description,
        argumentNames: (p.arguments ?? []).map((a) => a.name),
      });
    }
    cursor = page.nextCursor;
  } while (cursor);
  return out;
}

function readCapabilities(client: Client): ServerCapabilities {
  const caps = client.getServerCapabilities() ?? {};
  return {
    tools: caps.tools !== undefined,
    resources: caps.resources !== undefined,
    prompts: caps.prompts !== undefined,
    logging: caps.logging !== undefined,
    completions: caps.completions !== undefined,
    experimental: caps.experimental !== undefined,
  };
}

/**
 * Advertise sampling and elicitation, then refuse every such request and record it.
 *
 * We have to claim the capability for the server to attempt it at all — that is
 * the point. A well-behaved server sends nothing during a listing-only session;
 * one that reaches for your model or your user here is doing so unprompted.
 */
function trapUnsolicited(client: Client, sink: UnsolicitedRequest[]): void {
  const refuse = (method: string) => (request: { params?: unknown }) => {
    sink.push({
      method,
      preview: JSON.stringify(request.params ?? {}).slice(0, 200),
    });
    throw new Error("mcp-doctor performs read-only scans and does not service this request");
  };

  client.setRequestHandler(CreateMessageRequestSchema, refuse("sampling/createMessage"));
  client.setRequestHandler(ElicitRequestSchema, refuse("elicitation/create"));
}

/** Connect to one server and read its full surface. */
export async function scanServer(
  server: DeclaredServer,
  options: ScanOptions = {},
): Promise<ServerScan> {
  const opts = { ...DEFAULTS, ...options };
  const unsolicited: UnsolicitedRequest[] = [];
  const base: ServerScan = {
    name: server.name,
    declared: server,
    status: "skipped",
    tools: [],
    resources: [],
    resourceTemplates: [],
    prompts: [],
    unsolicited,
  };

  if (server.transport === "stdio" && !opts.allowSpawn) {
    return { ...base, note: "stdio scan needs --spawn (running it executes the server)" };
  }
  if (server.transport === "http" && !opts.allowNetwork) {
    return { ...base, note: "http scan needs --network (contacting it reveals you to the host)" };
  }
  if (server.transport === "unknown") {
    return { ...base, note: "could not determine transport from config" };
  }

  const started = Date.now();
  const client = new Client(
    IMPLEMENTATION,
    // Claimed so that a server willing to abuse them will actually try.
    { capabilities: { sampling: {}, elicitation: {} } },
  );
  trapUnsolicited(client, unsolicited);
  let transport: Transport;

  try {
    transport = buildTransport(server, opts);
  } catch (err) {
    return { ...base, status: "failed", note: err instanceof Error ? err.message : String(err) };
  }

  try {
    await withTimeout(client.connect(transport), opts.timeoutMs, "handshake");

    const capabilities = readCapabilities(client);
    const info = client.getServerVersion();

    // Only ask for what the server said it has. Calling tools/list on a server
    // that declared no tools capability is a guaranteed error.
    const tools = capabilities.tools
      ? await withTimeout(listAllTools(client), opts.timeoutMs, "tools/list")
      : [];
    const resources = capabilities.resources
      ? await withTimeout(listAllResources(client), opts.timeoutMs, "resources/list")
      : [];
    // Templates are optional even for servers that declare resources; a server
    // that does not implement the method must not fail the whole scan.
    const resourceTemplates = capabilities.resources
      ? await withTimeout(listAllResourceTemplates(client), opts.timeoutMs, "resources/templates/list").catch(
          () => [] as ResourceTemplateDef[],
        )
      : [];
    const prompts = capabilities.prompts
      ? await withTimeout(listAllPrompts(client), opts.timeoutMs, "prompts/list")
      : [];

    return {
      ...base,
      status: "ok",
      serverInfo: info ? { name: info.name, version: info.version } : undefined,
      capabilities,
      tools,
      resources,
      resourceTemplates,
      prompts,
      durationMs: Date.now() - started,
    };
  } catch (err) {
    return {
      ...base,
      status: "failed",
      note: describeError(err, server),
      durationMs: Date.now() - started,
    };
  } finally {
    await client.close().catch(() => {
      /* the process may already be gone; nothing useful to do */
    });
  }
}

/**
 * Present a server recovered from a log as an ordinary scan result.
 *
 * Nothing was executed to produce this, so the transport is recorded as
 * unknown and the note says where it came from.
 *
 * When the client truncated the listing, the server is marked skipped rather
 * than scanned. Reporting a partial tool list as a complete one would run the
 * rules over a fraction of the surface and come back clean — a confident wrong
 * answer about the tools that were never read.
 */
function fromLog(logged: LoggedServer): ServerScan {
  const declared: DeclaredServer = {
    name: logged.name,
    transport: "unknown",
    envKeys: [],
    source: { client: logged.client, path: logged.logPath, serverCount: 1 },
  };

  const base = {
    name: logged.name,
    declared,
    serverInfo: logged.serverInfo,
    resources: [],
    resourceTemplates: [],
    prompts: logged.prompts,
    unsolicited: [],
    discoveredVia: "log" as const,
  };

  if (!logged.listingComplete) {
    return {
      ...base,
      status: "skipped",
      note:
        "found in " +
        logged.client +
        " logs, but the client truncated its tool listing. There is no command to " +
        "start it from either, so its tools cannot be read from here — inspect it in " +
        "the client's own extensions list",
      tools: [],
    };
  }

  return {
    ...base,
    status: "ok",
    note: "recovered from " + logged.client + " logs; not executed",
    tools: logged.tools,
  };
}

/** Scan every server found by discovery. */
export async function scanAll(
  discovery: DiscoveryResult,
  options: ScanOptions = {},
): Promise<ScanResult> {
  const opts = { ...DEFAULTS, ...options };

  // Snapshot the process table *before* scanning. With --spawn we start servers
  // ourselves, and npx-style launchers leave orphans whose parent pid no longer
  // resolves — so afterwards our own children can look like someone else's.
  // Reading the table executes nothing and contacts nobody, so it runs by
  // default; unlike --spawn and --network it costs the user nothing.
  const live = opts.checkLive ? findLiveServers(discovery.servers) : undefined;

  const servers: ServerScan[] = [];
  // Sequential on purpose: parallel spawning of unknown binaries is exactly
  // the kind of thing this tool exists to warn people about.
  for (const declared of discovery.servers) {
    servers.push(await scanServer(declared, options));
  }

  /*
   * Fold in anything the client logged but no config declares.
   *
   * These arrive as ordinary scan results, so every existing rule — annotation
   * lies, poisoning, unbounded parameters, cross-server chains — applies to
   * them without a line of special handling. The tools came from a recorded
   * handshake rather than a live one, which means we get them without starting
   * anything at all.
   */
  let logs: LogSummary | undefined;
  if (opts.readLogs) {
    const read = readClientLogs();
    const declaredNames = new Set(discovery.servers.map((s) => s.name.toLowerCase()));
    const undeclared: string[] = [];

    for (const logged of read.servers) {
      if (declaredNames.has(logged.name.toLowerCase())) continue;
      undeclared.push(logged.name);
      servers.push(fromLog(logged));
    }

    logs = {
      checkedDirs: read.checkedDirs,
      supportedClients: read.supportedClients,
      undeclared,
    };
  }

  return { scannedAt: new Date().toISOString(), discovery, servers, live, logs };
}
