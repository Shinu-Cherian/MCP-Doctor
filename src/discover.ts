/**
 * Stage 1: find every place an MCP server can be declared, and read them.
 *
 * Each AI app invented its own file location and its own JSON shape, so the
 * job here is to normalise all of them into one `DeclaredServer[]`.
 */

import { readFileSync, existsSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";
import { parse as parseJsonc, type ParseError } from "jsonc-parser";
import type {
  ClientKind,
  ConfigSource,
  DeclaredServer,
  DiscoveryResult,
  Transport,
} from "./types.js";

/** A config file location we know about. */
interface KnownLocation {
  client: ClientKind;
  path: string;
  /** Top-level key holding the server map. VS Code uses "servers", everyone else "mcpServers". */
  key: "mcpServers" | "servers";
}

/**
 * Where each client keeps its config, per OS.
 * Missing files are fine — we report which paths were checked either way, so
 * "we looked and found nothing" is distinguishable from "we never looked".
 */
function knownLocations(): KnownLocation[] {
  const home = homedir();
  const os = platform();

  const appData =
    process.env.APPDATA ?? join(home, "AppData", "Roaming");

  const claudeDesktop =
    os === "win32"
      ? join(appData, "Claude", "claude_desktop_config.json")
      : os === "darwin"
        ? join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
        : join(home, ".config", "Claude", "claude_desktop_config.json");

  const vscodeUser =
    os === "win32"
      ? join(appData, "Code", "User", "mcp.json")
      : os === "darwin"
        ? join(home, "Library", "Application Support", "Code", "User", "mcp.json")
        : join(home, ".config", "Code", "User", "mcp.json");

  return [
    { client: "claude-desktop", path: claudeDesktop, key: "mcpServers" },
    { client: "claude-code", path: join(home, ".claude.json"), key: "mcpServers" },
    { client: "cursor", path: join(home, ".cursor", "mcp.json"), key: "mcpServers" },
    { client: "vscode", path: vscodeUser, key: "servers" },
    {
      client: "windsurf",
      path: join(home, ".codeium", "windsurf", "mcp_config.json"),
      key: "mcpServers",
    },
  ];
}

/** Per-project config files, relative to a project directory. */
function projectLocations(dir: string): KnownLocation[] {
  return [
    { client: "project", path: join(dir, ".mcp.json"), key: "mcpServers" },
    { client: "project", path: join(dir, ".vscode", "mcp.json"), key: "servers" },
    { client: "project", path: join(dir, ".cursor", "mcp.json"), key: "mcpServers" },
  ];
}

/**
 * Parse JSON that may contain comments and trailing commas.
 * VS Code's mcp.json legitimately has both; plain JSON.parse would throw.
 */
function readJsonc(path: string): unknown {
  // Strip a UTF-8 BOM. Notepad, `Out-File -Encoding utf8` and several editors
  // add one; it is invisible in every editor and makes the parser fail at
  // offset 0, which would silently drop a real config file.
  const text = readFileSync(path, "utf8").replace(/^﻿/, "");
  const errors: ParseError[] = [];
  const value = parseJsonc(text, errors, {
    allowTrailingComma: true,
    disallowComments: false,
  });
  if (errors.length > 0) {
    throw new Error(`malformed JSON near offset ${errors[0].offset}`);
  }
  return value;
}

/**
 * Work out how a server entry is reached.
 * An explicit `type` wins; otherwise `command` implies a local process and
 * `url` implies a remote endpoint.
 */
function detectTransport(entry: Record<string, unknown>): Transport {
  const declared = typeof entry.type === "string" ? entry.type.toLowerCase() : undefined;
  if (declared === "stdio") return "stdio";
  if (declared === "http" || declared === "sse" || declared === "streamable-http") return "http";
  if (typeof entry.command === "string") return "stdio";
  if (typeof entry.url === "string") return "http";
  return "unknown";
}

/** Turn one raw config entry into our normalised shape. */
function normaliseEntry(
  name: string,
  raw: unknown,
  source: ConfigSource,
): DeclaredServer | null {
  if (typeof raw !== "object" || raw === null) return null;
  const entry = raw as Record<string, unknown>;

  // Names only — see the rule at the top of types.ts.
  const envKeys =
    typeof entry.env === "object" && entry.env !== null
      ? Object.keys(entry.env as Record<string, unknown>)
      : [];

  return {
    name,
    transport: detectTransport(entry),
    command: typeof entry.command === "string" ? entry.command : undefined,
    args: Array.isArray(entry.args) ? entry.args.map(String) : undefined,
    url: typeof entry.url === "string" ? entry.url : undefined,
    envKeys,
    source,
  };
}

/** Pull a `{ name: entry }` map out of a parsed config object. */
function collectFromMap(
  map: unknown,
  source: ConfigSource,
): DeclaredServer[] {
  if (typeof map !== "object" || map === null) return [];
  const out: DeclaredServer[] = [];
  for (const [name, raw] of Object.entries(map as Record<string, unknown>)) {
    const server = normaliseEntry(name, raw, source);
    if (server) out.push(server);
  }
  return out;
}

/**
 * Scan every known config location plus any extra project directories.
 */
export function discover(projectDirs: string[] = []): DiscoveryResult {
  const locations = [
    ...knownLocations(),
    ...projectDirs.flatMap((d) => projectLocations(resolve(d))),
  ];

  const result: DiscoveryResult = {
    scannedAt: new Date().toISOString(),
    platform: platform(),
    checkedPaths: locations.map((l) => l.path),
    sources: [],
    servers: [],
    errors: [],
  };

  for (const loc of locations) {
    if (!existsSync(loc.path)) continue;

    let parsed: unknown;
    try {
      parsed = readJsonc(loc.path);
    } catch (err) {
      result.errors.push({
        path: loc.path,
        message: err instanceof Error ? err.message : String(err),
      });
      continue;
    }

    if (typeof parsed !== "object" || parsed === null) continue;
    const root = parsed as Record<string, unknown>;

    const source: ConfigSource = { client: loc.client, path: loc.path, serverCount: 0 };
    const found: DeclaredServer[] = [];

    // The normal case: a top-level server map.
    found.push(...collectFromMap(root[loc.key], source));

    // Claude Code also stores per-project server maps under `projects`.
    // Missing these is how a scanner ends up reporting "0 servers" on a machine
    // that is in fact running several.
    if (typeof root.projects === "object" && root.projects !== null) {
      for (const [projectPath, cfg] of Object.entries(
        root.projects as Record<string, unknown>,
      )) {
        if (typeof cfg !== "object" || cfg === null) continue;
        const nested = (cfg as Record<string, unknown>).mcpServers;
        const perProject: ConfigSource = {
          client: loc.client,
          path: `${loc.path} → projects["${projectPath}"]`,
          serverCount: 0,
        };
        const servers = collectFromMap(nested, perProject);
        if (servers.length > 0) {
          perProject.serverCount = servers.length;
          result.sources.push(perProject);
          result.servers.push(...servers);
        }
      }
    }

    source.serverCount = found.length;
    result.sources.push(source);
    result.servers.push(...found);
  }

  return result;
}
