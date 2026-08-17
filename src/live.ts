/**
 * What is actually running, as opposed to what the config files claim.
 *
 * Config discovery answers "what did someone write down". This answers "what
 * is on this machine right now", and the gap between the two is the finding.
 *
 * Every stdio MCP server is a child process of the client that launched it, so
 * the operating system knows about it regardless of which application started
 * it or where that application keeps its settings. That makes process
 * enumeration the one detection method that works the same for Claude, Cursor,
 * VS Code and Windsurf alike.
 *
 * Enumeration and analysis are separated deliberately: `listProcesses` touches
 * the OS, `detectLiveServers` is pure. The interesting logic is therefore
 * testable against synthetic process tables rather than whatever happens to be
 * running on the machine running the tests.
 */

import { spawnSync } from "node:child_process";
import { basename } from "node:path";
import type { DeclaredServer, LiveResult, LiveServer, RunningProcess } from "./types.js";

/** Applications known to launch MCP servers. */
const CLIENT_BINARIES =
  /^(claude|cursor|code|code - insiders|codium|windsurf|zed|electron)(\.exe)?$/i;

/**
 * Programs that run a script rather than being one.
 *
 * An MCP server is nearly always launched through one of these, because the
 * server itself ships as a package rather than a compiled binary.
 */
const SCRIPT_RUNNER = /^(node|npx|bun|bunx|deno|python3?|uv|uvx|pipx|pnpm|yarn|dotnet)(\.exe)?$/i;

/**
 * Child processes a client spawns for its own reasons.
 *
 * Editors fork renderers, language servers, extension hosts and shells
 * constantly. Reporting those as MCP servers would bury the real finding under
 * noise, which is the failure mode this tool exists to avoid.
 */
const NOT_A_SERVER =
  /^(powershell|pwsh|cmd|conhost|bash|sh|zsh|fish|git|ssh|rg|fzf|tsc|eslint|prettier|esbuild|vite|webpack|jest|vitest)(\.exe)?$/i;

/**
 * Text that marks a token as MCP-related.
 *
 * "mcp" must be joined to something — `mcp-server-git`, `server_mcp`,
 * `@modelcontextprotocol/...`. A bare "mcp" is rejected because it is far more
 * likely to be a directory someone named than a package: an unquoted Windows
 * path like `C:\proj\mcp thing\...` splits on the space and leaves a fragment
 * ending in exactly that.
 */
const MCP_HINT = /(^|[/@])mcp[-_]|[-_]mcp([-_./]|$)|modelcontextprotocol/i;

/** Does this argument look like a filesystem path rather than a package spec? */
function isPathLike(token: string): boolean {
  return token.startsWith("/") || token.startsWith(".") || /^[A-Za-z]:[\\/]/.test(token) || token.includes("\\");
}

/**
 * Test a command line for MCP-ness, one argument at a time.
 *
 * Matching the raw command line is too loose: a project checked out to
 * `C:\dev\MCP server\` puts "MCP" in the path of every command run from it,
 * and every one of those would be reported as a server. Path-like arguments
 * are therefore reduced to their filename, so a parent directory's name never
 * decides the answer.
 */
export function mentionsMcp(command: string): boolean {
  for (const token of splitCommand(command)) {
    const subject = isPathLike(token)
      ? token.replace(/\\/g, "/").split("/").filter(Boolean).pop() ?? ""
      : token;
    if (MCP_HINT.test(subject)) return true;
  }
  return false;
}

/* ------------------------------------------------------------------ *
 * OS access
 * ------------------------------------------------------------------ */

/** Split a command line into argv, respecting double quotes. */
export function splitCommand(command: string): string[] {
  const out: string[] = [];
  let current = "";
  let quoted = false;

  for (const char of command) {
    if (char === '"') {
      quoted = !quoted;
    } else if (/\s/.test(char) && !quoted) {
      if (current) out.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  if (current) out.push(current);
  return out;
}

function listProcessesWindows(): RunningProcess[] {
  // CIM rather than `wmic`, which is deprecated and absent on newer Windows.
  const script =
    "Get-CimInstance Win32_Process | Select-Object " +
    "@{n='pid';e={$_.ProcessId}},@{n='ppid';e={$_.ParentProcessId}}," +
    "@{n='command';e={if($_.CommandLine){$_.CommandLine}else{$_.Name}}} | ConvertTo-Json -Compress";

  const result = spawnSync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    { encoding: "utf8", maxBuffer: 32 * 1024 * 1024, windowsHide: true },
  );
  if (result.status !== 0 || !result.stdout) return [];

  try {
    const parsed = JSON.parse(result.stdout) as RunningProcess[] | RunningProcess;
    const rows = Array.isArray(parsed) ? parsed : [parsed];
    return rows.filter((r) => typeof r.pid === "number" && typeof r.command === "string");
  } catch {
    return [];
  }
}

function listProcessesPosix(): RunningProcess[] {
  // `=` on each field suppresses the header, so there is nothing to skip.
  const result = spawnSync("ps", ["-axo", "pid=,ppid=,command="], {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0 || !result.stdout) return [];

  const rows: RunningProcess[] = [];
  for (const line of result.stdout.split("\n")) {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
    if (!match) continue;
    rows.push({ pid: Number(match[1]), ppid: Number(match[2]), command: match[3].trim() });
  }
  return rows;
}

/** Read the process table, or return an empty list if the platform will not say. */
export function listProcesses(): RunningProcess[] {
  try {
    return process.platform === "win32" ? listProcessesWindows() : listProcessesPosix();
  } catch {
    return [];
  }
}

/* ------------------------------------------------------------------ *
 * Analysis (pure)
 * ------------------------------------------------------------------ */

/** The executable name from a command line, lowercased and without extension. */
function executableName(command: string): string {
  const [first] = splitCommand(command);
  if (!first) return "";
  return basename(first).toLowerCase();
}

/**
 * Walk up the process tree looking for a client application.
 *
 * A server launched by Cursor may sit several levels below it — a shim, a
 * package runner, then the server itself — so checking only the direct parent
 * misses real cases.
 */
function findClientAncestor(
  proc: RunningProcess,
  byPid: Map<number, RunningProcess>,
): string | undefined {
  const seen = new Set<number>([proc.pid]);
  let current = byPid.get(proc.ppid);
  let depth = 0;

  while (current && depth < 12 && !seen.has(current.pid)) {
    seen.add(current.pid);
    const name = executableName(current.command).replace(/\.exe$/, "");
    if (CLIENT_BINARIES.test(name)) return name;
    current = byPid.get(current.ppid);
    depth += 1;
  }
  return undefined;
}

/** Normalise a command line so a declared entry and a live one can be compared. */
function normalise(text: string): string {
  return text.toLowerCase().replace(/\\/g, "/").replace(/\s+/g, " ").trim();
}

/** Does this running process correspond to something a config file declared? */
function matchDeclared(
  proc: RunningProcess,
  declared: DeclaredServer[],
): DeclaredServer | undefined {
  const live = normalise(proc.command);
  return declared.find((server) => {
    if (server.transport !== "stdio" || !server.command) return false;
    // Compare on the distinguishing argument — usually the package or script
    // name. Absolute paths and quoting differ too much for equality to work.
    const parts = [server.command, ...(server.args ?? [])].map(normalise);
    const distinguishing = parts.filter((p) => p.length > 2 && !p.startsWith("-"));
    return distinguishing.length > 0 && distinguishing.every((p) => live.includes(p));
  });
}

/**
 * Every pid belonging to our own invocation: this process, what launched it,
 * and anything it launched.
 *
 * mcp-doctor runs through a script runner, from a directory that may well have
 * "mcp" in its name, spawned by the very client we are looking for children of.
 * Without this it reports itself, every time.
 */
export function selfTree(processes: RunningProcess[], selfPid: number): Set<number> {
  const byPid = new Map(processes.map((p) => [p.pid, p]));
  const tree = new Set<number>([selfPid]);

  // Ancestors, stopping at a client — the client's other children are fair game.
  let current = byPid.get(selfPid);
  let depth = 0;
  while (current && depth < 12) {
    const parent = byPid.get(current.ppid);
    if (!parent) break;
    const name = executableName(parent.command).replace(/\.exe$/, "");
    if (CLIENT_BINARIES.test(name)) break;
    if (tree.has(parent.pid)) break;
    tree.add(parent.pid);
    current = parent;
    depth += 1;
  }

  // Descendants, however deep.
  let grew = true;
  while (grew) {
    grew = false;
    for (const proc of processes) {
      if (!tree.has(proc.pid) && tree.has(proc.ppid)) {
        tree.add(proc.pid);
        grew = true;
      }
    }
  }

  return tree;
}

/**
 * Decide which running processes are MCP servers.
 *
 * Deliberately conservative: a false positive here tells someone their machine
 * is running something it is not, which is worse than staying quiet.
 */
export function detectLiveServers(
  processes: RunningProcess[],
  declared: DeclaredServer[] = [],
  selfPid: number = process.pid,
): LiveServer[] {
  const byPid = new Map(processes.map((p) => [p.pid, p]));
  const ours = selfTree(processes, selfPid);
  const found: LiveServer[] = [];

  for (const proc of processes) {
    if (ours.has(proc.pid)) continue;

    const exe = executableName(proc.command);
    if (!exe) continue;

    // Never report the client itself, or the helpers it spawns for other work.
    if (CLIENT_BINARIES.test(exe.replace(/\.exe$/, ""))) continue;
    if (NOT_A_SERVER.test(exe.replace(/\.exe$/, ""))) continue;

    const declaredMatch = matchDeclared(proc, declared);
    const client = findClientAncestor(proc, byPid);
    const mcpish = mentionsMcp(proc.command);
    const isRunner = SCRIPT_RUNNER.test(exe.replace(/\.exe$/, ""));

    let reason: string | undefined;
    if (declaredMatch) {
      reason = `matches "${declaredMatch.name}" in ${declaredMatch.source.client} config`;
    } else if (client && isRunner && mcpish) {
      reason = `${client} spawned a script runner whose command mentions MCP`;
    } else if (client && mcpish) {
      reason = `${client} spawned a process whose command mentions MCP`;
    } else if (isRunner && mcpish) {
      reason = "script runner with MCP in its command line";
    }

    if (!reason) continue;

    found.push({
      pid: proc.pid,
      command: proc.command,
      client,
      declaredAs: declaredMatch?.name,
      reason,
    });
  }

  return found;
}

/** Enumerate and analyse in one step. */
export function findLiveServers(declared: DeclaredServer[] = []): LiveResult {
  const processes = listProcesses();

  if (processes.length === 0) {
    return {
      supported: false,
      examined: 0,
      servers: [],
      note:
        process.platform === "win32"
          ? "could not read the process table (PowerShell unavailable?)"
          : "could not read the process table (`ps` unavailable?)",
    };
  }

  return {
    supported: true,
    examined: processes.length,
    servers: detectLiveServers(processes, declared),
  };
}
