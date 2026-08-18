/**
 * A third place to look: what the client wrote down about servers it has run.
 *
 * Config files record intent and the process table records this moment. Neither
 * sees a server installed as an extension that runs inside the client's own
 * process — it never appears in `mcpServers`, and it never becomes a child
 * process to enumerate. On the machine this was written on, that describes the
 * only MCP server actually installed.
 *
 * Clients that keep a per-server log leave the whole handshake on disk:
 * identity, and the full `tools/list` reply with every description and schema.
 * Reading it recovers the same material a live scan would, without starting
 * anything — which makes it both safer than `--spawn` and the only way to see
 * a server that cannot be started on demand.
 *
 * Only Claude Desktop is supported so far. Cursor and VS Code route MCP logs to
 * an editor output panel rather than a file, and Windsurf documents no
 * location, so there is nothing to read for those yet. The report names the
 * clients it covered rather than implying it looked everywhere.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir, platform } from "node:os";
import { basename, join } from "node:path";
import type { ClientKind, LoggedServer, PromptDef, ToolDef } from "./types.js";

interface LogLocation {
  client: ClientKind;
  dir: string;
}

/** Where each client keeps per-server MCP logs, per OS. */
export function knownLogLocations(): LogLocation[] {
  const home = homedir();
  const os = platform();
  const appData = process.env.APPDATA ?? join(home, "AppData", "Roaming");

  const claudeDesktop =
    os === "win32"
      ? join(appData, "Claude", "logs")
      : os === "darwin"
        ? join(home, "Library", "Logs", "Claude")
        : join(home, ".config", "Claude", "logs");

  return [{ client: "claude-desktop", dir: claudeDesktop }];
}

/**
 * Extract the first complete JSON object on a line.
 *
 * Brace counting rather than a regex, because tool descriptions routinely
 * contain braces and quotes of their own; and string-aware, so a `}` inside a
 * description cannot close the object early.
 */
export function firstJsonObject(line: string): unknown {
  const start = line.indexOf("{");
  if (start === -1) return undefined;

  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = start; i < line.length; i += 1) {
    const ch = line[i];

    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inString = !inString;
      continue;
    }
    if (inString) continue;

    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) {
        try {
          return JSON.parse(line.slice(start, i + 1));
        } catch {
          return undefined;
        }
      }
    }
  }

  return undefined;
}

function toolsFrom(result: Record<string, unknown>): ToolDef[] | undefined {
  const tools = result.tools;
  if (!Array.isArray(tools)) return undefined;

  return tools.flatMap((raw) => {
    if (typeof raw !== "object" || raw === null) return [];
    const t = raw as Record<string, unknown>;
    if (typeof t.name !== "string") return [];
    return [
      {
        name: t.name,
        description: typeof t.description === "string" ? t.description : undefined,
        inputSchema: (t.inputSchema ?? undefined) as Record<string, unknown> | undefined,
        outputSchema: (t.outputSchema ?? undefined) as Record<string, unknown> | undefined,
        annotations: (t.annotations ?? undefined) as ToolDef["annotations"],
      },
    ];
  });
}

function promptsFrom(result: Record<string, unknown>): PromptDef[] | undefined {
  const prompts = result.prompts;
  if (!Array.isArray(prompts)) return undefined;

  return prompts.flatMap((raw) => {
    if (typeof raw !== "object" || raw === null) return [];
    const p = raw as Record<string, unknown>;
    if (typeof p.name !== "string") return [];
    const args = Array.isArray(p.arguments) ? p.arguments : [];
    return [
      {
        name: p.name,
        description: typeof p.description === "string" ? p.description : undefined,
        argumentNames: args.flatMap((a) =>
          typeof a === "object" && a !== null && typeof (a as { name?: unknown }).name === "string"
            ? [(a as { name: string }).name]
            : [],
        ),
      },
    ];
  });
}

function identityFrom(result: Record<string, unknown>): { name: string; version: string } | undefined {
  const info = result.serverInfo;
  if (typeof info !== "object" || info === null) return undefined;
  const i = info as Record<string, unknown>;
  if (typeof i.name !== "string") return undefined;
  return { name: i.name, version: typeof i.version === "string" ? i.version : "unknown" };
}

/** Claude Desktop replaces the middle of a long message with this. */
const TRUNCATION = /\[\d[\d,]* chars truncated\]/;

/** Identity survives truncation: it sits at the start of the payload. */
const SERVER_INFO = /"serverInfo":{"name":"([^"]+)","version":"([^"]*)"/;

/**
 * Read one `mcp-server-NAME.log`.
 *
 * Logs are appended across sessions, so later lines win: the most recent
 * listing describes what is installed now.
 *
 * The client truncates long payloads, which is fatal for tool listings and
 * survivable for everything else. When that happens the listing is marked
 * incomplete rather than reported as a short one — a partial list run through
 * the rules would come back clean for tools that were never read.
 */
export function parseServerLog(
  text: string,
  name: string,
  client: ClientKind,
  logPath: string,
  lastSeen?: string,
): LoggedServer {
  let tools: ToolDef[] = [];
  let prompts: PromptDef[] = [];
  let serverInfo: { name: string; version: string } | undefined;
  let listingComplete = true;
  let partialToolNames: string[] = [];

  for (const line of text.split("\n")) {
    if (!line.includes('"result"')) continue;

    const truncated = TRUNCATION.test(line);
    const carriesTools = line.includes('"tools":[');

    if (truncated) {
      if (carriesTools) {
        listingComplete = false;
        partialToolNames = [...line.matchAll(/"name":"([^"]+)"/g)].map((m) => m[1]);
      }
      const info = line.match(SERVER_INFO);
      if (info) serverInfo = { name: info[1], version: info[2] || "unknown" };
      continue;
    }

    const parsed = firstJsonObject(line);
    if (typeof parsed !== "object" || parsed === null) continue;

    const result = (parsed as { result?: unknown }).result;
    if (typeof result !== "object" || result === null) continue;
    const r = result as Record<string, unknown>;

    const t = toolsFrom(r);
    if (t) { tools = t; listingComplete = true; partialToolNames = []; }

    const p = promptsFrom(r);
    if (p) prompts = p;

    const info = identityFrom(r);
    if (info) serverInfo = info;
  }

  return {
    name,
    client,
    logPath,
    serverInfo,
    tools,
    prompts,
    lastSeen,
    listingComplete,
    partialToolNames,
  };
}

function readServerLog(path: string, client: ClientKind): LoggedServer | null {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return null;
  }

  const name = basename(path).replace(/^mcp-server-/, "").replace(/\.log$/, "");
  if (!name) return null;

  let lastSeen: string | undefined;
  try {
    lastSeen = statSync(path).mtime.toISOString();
  } catch {
    /* mtime is a nicety, not a requirement */
  }

  return parseServerLog(text, name, client, path, lastSeen);
}

export interface LogReadResult {
  /** Directories examined, whether or not they existed. */
  checkedDirs: string[];
  /** Clients whose log format this tool can read at all. */
  supportedClients: ClientKind[];
  servers: LoggedServer[];
}

/** Read every per-server log this tool knows how to find. */
export function readClientLogs(): LogReadResult {
  const locations = knownLogLocations();
  const servers: LoggedServer[] = [];

  for (const loc of locations) {
    if (!existsSync(loc.dir)) continue;

    let entries: string[];
    try {
      entries = readdirSync(loc.dir);
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!/^mcp-server-.+\.log$/i.test(entry)) continue;
      const server = readServerLog(join(loc.dir, entry), loc.client);
      if (server) servers.push(server);
    }
  }

  return {
    checkedDirs: locations.map((l) => l.dir),
    supportedClients: locations.map((l) => l.client),
    servers,
  };
}
